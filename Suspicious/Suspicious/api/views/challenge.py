import logging

from django.db import IntegrityError, transaction
from django.http import HttpResponseRedirect
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from case_handler.models import CaseChallengeToken
from tasp.services.challenge import get_submissions_url, run_case_challenge

from api.serializers.challenge import CaseChallengeTokenQuerySerializer

logger = logging.getLogger(__name__)

class InvalidOrExpiredChallengeToken(Exception):
    pass


class CaseChallengeTokenView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, case_id: int):
        query_serializer = CaseChallengeTokenQuerySerializer(data=request.query_params)
        query_serializer.is_valid(raise_exception=True)

        token = query_serializer.validated_data["token"]

        try:
            token_record = self._consume_token(case_id=case_id, raw_token=token)

            case = token_record.case

            transaction.on_commit(lambda: run_case_challenge(case, logger))

        except InvalidOrExpiredChallengeToken:
            return Response(
                {"detail": "Invalid or expired token."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except ValueError as exc:
            logger.info(
                "Case challenge conflict for case_id=%s: %s",
                case_id,
                str(exc),
            )
            return Response(
                {"detail": str(exc)},
                status=status.HTTP_409_CONFLICT,
            )
        except IntegrityError:
            logger.exception("Database integrity error while challenging case_id=%s", case_id)
            return Response(
                {"detail": "Database error processing challenge."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        except Exception:
            logger.exception("Unexpected error while challenging case_id=%s", case_id)
            return Response(
                {"detail": "Unexpected error processing challenge."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return HttpResponseRedirect(get_submissions_url())

    @staticmethod
    def _consume_token(*, case_id: int, raw_token: str) -> CaseChallengeToken:
        token_hash = CaseChallengeToken.hash_token(raw_token)
        now = timezone.now()

        with transaction.atomic():
            token_record = (
                CaseChallengeToken.objects.select_for_update()
                .select_related("case", "case__reporter")
                .filter(
                    token_hash=token_hash,
                    case_id=case_id,
                    used_at__isnull=True,
                    expires_at__gt=now,
                )
                .first()
            )

            if token_record is None:
                raise InvalidOrExpiredChallengeToken()

            token_record.mark_used()
            return token_record