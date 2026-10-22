import logging

from django.db import transaction
from django.http import HttpResponse, HttpResponseRedirect
from django.template.loader import render_to_string
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from case_handler.models import CaseChallengeToken
from tasp.services.challenge import CaseChallengeService, get_submissions_url, notify_and_record_challenge

from api.serializers.challenge import (
    MIN_REASON_LENGTH,
    CaseChallengeTokenQuerySerializer,
    SubmissionChallengeSerializer,
)

logger = logging.getLogger(__name__)

class InvalidOrExpiredChallengeToken(Exception):
    pass


class CaseChallengeTokenView(APIView):
    """The emailed challenge link.

    GET only shows a form: mail scanners and link previews fetch links, so a GET
    must never change the case or spend the token. POST (reason and proposed
    verdict required) spends the token and challenges the case in one transaction.
    """
    permission_classes = [AllowAny]

    @staticmethod
    def _token(request, token):
        if token is None:
            query = CaseChallengeTokenQuerySerializer(data=request.query_params)
            query.is_valid(raise_exception=True)
            return query.validated_data["token"]
        return token.strip()

    @staticmethod
    def _form(case, status_code=200, errors=(), data=None):
        data = data or {}
        html = render_to_string("api/challenge_confirm.html", {
            "case_id": case.id, "result": case.results, "errors": errors, "min_reason": MIN_REASON_LENGTH,
            "proposed": data.get("proposed_result", ""), "reason": data.get("reason", ""),
        })
        return HttpResponse(html, status=status_code)

    def get(self, request, case_id: int, token: str | None = None):
        raw = self._token(request, token)
        if not raw:
            return Response({"detail": "Token is required."}, status=status.HTTP_400_BAD_REQUEST)
        record = self._find_token(case_id=case_id, raw_token=raw)
        if record is None:
            return Response({"detail": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)
        if record.case.is_challenged:
            return Response({"detail": "Case already challenged"}, status=status.HTTP_409_CONFLICT)
        return self._form(record.case)

    def post(self, request, case_id: int, token: str | None = None):
        raw = self._token(request, token)
        form = SubmissionChallengeSerializer(data=request.data)
        try:
            with transaction.atomic():
                record = self._consume_token(case_id=case_id, raw_token=raw, spend=form.is_valid())
                if not form.is_valid():
                    errors = [m for msgs in form.errors.values() for m in msgs]
                    return self._form(record.case, 400, errors, request.data)
                case = record.case
                CaseChallengeService(case, logger).mark_challenged(
                    form.validated_data["proposed_result"], form.validated_data["reason"])
        except InvalidOrExpiredChallengeToken:
            return Response({"detail": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)
        except ValueError as exc:
            # codeql[py/stack-trace-exposure]: the only ValueError reachable here is
            # mark_challenged()'s fixed "Case already challenged" literal.
            return Response({"detail": str(exc)}, status=status.HTTP_409_CONFLICT)
        except Exception:
            logger.exception("Unexpected error while challenging case_id=%s", case_id)
            return Response({"detail": "Unexpected error processing challenge."},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        try:
            notify_and_record_challenge(case, logger)
        except Exception:
            # the challenge is recorded; a failed alert must not turn it into an error page
            logger.exception("Challenge notify failed for case %s", case.id)
        return HttpResponseRedirect(get_submissions_url())

    @staticmethod
    def _find_token(*, case_id: int, raw_token: str):
        return (
            CaseChallengeToken.objects.select_related("case", "case__reporter")
            .filter(token_hash=CaseChallengeToken.hash_token(raw_token), case_id=case_id,
                    used_at__isnull=True, expires_at__gt=timezone.now())
            .first()
        )

    @staticmethod
    def _consume_token(*, case_id: int, raw_token: str, spend: bool = True) -> CaseChallengeToken:
        """The token row under lock; marked used only when `spend` (a rejected form
        leaves the link usable). Runs inside the caller's transaction, so a failed
        challenge rolls the spend back."""
        record = (
            CaseChallengeToken.objects.select_for_update()
            .select_related("case", "case__reporter")
            .filter(token_hash=CaseChallengeToken.hash_token(raw_token), case_id=case_id,
                    used_at__isnull=True, expires_at__gt=timezone.now())
            .first()
        )
        if record is None:
            raise InvalidOrExpiredChallengeToken()
        if spend:
            record.mark_used()
        return record
