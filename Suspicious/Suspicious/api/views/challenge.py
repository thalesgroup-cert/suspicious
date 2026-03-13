from django.db import IntegrityError, transaction
from django.http import HttpResponseRedirect
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from case_handler.models import CaseChallengeToken

from django.utils import timezone
from tasp.services.challenge import get_submissions_url, run_case_challenge
import logging

logger = logging.getLogger(__name__)

class CaseChallengeTokenView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, case_id: int):
        token = request.query_params.get("token")
        if not token:
            return Response({"detail": "Token is required."}, status=400)

        token_hash = CaseChallengeToken.hash_token(token)
        now = timezone.now()
        try:
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
                if not token_record:
                    return Response({"detail": "Invalid or expired token."}, status=400)

                run_case_challenge(token_record.case, logger)
                token_record.mark_used()
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=409)
        except IntegrityError:
            logger.exception("Database integrity error challenging case %s", case_id)
            return Response({"detail": "Database error processing challenge."}, status=500)
        except Exception:
            logger.exception("Unexpected error challenging case %s", case_id)
            return Response({"detail": "Unexpected error processing challenge."}, status=500)

        return HttpResponseRedirect(get_submissions_url())




    