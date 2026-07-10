"""POST /api/cortex/webhook/ — Cortex job-completion callback.

Cortex calls this endpoint when a job finishes (Success or Failure).
We look up which cases own the job via the CaseAnalyzerJob ledger
(written atomically at dispatch time) and dispatch `reconcile_case` for each
owning case instead of waiting for the cron poll fallback.

Authentication: Bearer <CORTEX_WEBHOOK_SECRET> in the Authorization header,
compared via hmac.compare_digest to defeat timing oracles.
The cron poll (update_ongoing_cases beat task) remains active as a
fallback for any webhook deliveries that are missed or delayed.

Idempotency: each jobId is recorded in Redis (TTL 1h) on first delivery;
duplicate webhook deliveries (Cortex retry, network resend) short-circuit.
"""
import hmac
import logging

from django.conf import settings
from django.core.cache import cache
from rest_framework import status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

logger = logging.getLogger(__name__)

_WEBHOOK_DEDUP_TTL = 3600


def _find_cases_for_job(job_id: str) -> list[int]:
    """Return case IDs awaiting this Cortex job. O(1) indexed lookup.

    Uses the CaseAnalyzerJob ledger written atomically at dispatch time.
    Returns the IDs of cases that still have a pending CaseAnalyzerJob row
    for this jobId. Cases whose CAJ row has already transitioned to
    Success/Failure/Deleted are not returned — those re-deliveries are
    no-ops.
    """
    from cortex_job.models import CaseAnalyzerJob
    return list(
        CaseAnalyzerJob.objects
        .filter(cortex_job_id=job_id, status__in=CaseAnalyzerJob.PENDING_STATUSES)
        .values_list("case_id", flat=True)
        .distinct()
    )


class CortexWebhookView(APIView):
    authentication_classes = []
    permission_classes = []
    throttle_classes = []

    def post(self, request: Request) -> Response:
        # ── Authenticate ────────────────────────────────────────────────────
        secret = getattr(settings, "CORTEX_WEBHOOK_SECRET", "")
        if not secret:
            logger.error("CORTEX_WEBHOOK_SECRET not configured — webhook rejected")
            return Response({"detail": "Webhook not configured."}, status=status.HTTP_503_SERVICE_UNAVAILABLE)

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer ") or not hmac.compare_digest(auth_header[7:], secret):
            logger.warning("Cortex webhook: invalid or missing Authorization header")
            return Response({"detail": "Unauthorized."}, status=status.HTTP_401_UNAUTHORIZED)

        # ── Parse payload ────────────────────────────────────────────────────
        job_id = request.data.get("jobId") or request.data.get("job_id")
        if not job_id:
            return Response({"detail": "jobId is required."}, status=status.HTTP_400_BAD_REQUEST)

        job_id = str(job_id).strip()
        logger.info("Cortex webhook received for jobId=%s", job_id)

        # ── Idempotency: drop duplicate deliveries for the same jobId ────────
        if not cache.add(f"cortex_job_processed:{job_id}", 1, timeout=_WEBHOOK_DEDUP_TTL):
            logger.info("Cortex webhook duplicate jobId=%s; skipping", job_id)
            return Response({"detail": "Already processed."}, status=status.HTTP_200_OK)

        # ── Dispatch targeted case update(s) ─────────────────────────────────
        case_ids = _find_cases_for_job(job_id)
        if not case_ids:
            logger.info(
                "No pending CaseAnalyzerJob for jobId=%s; cron fallback covers it", job_id
            )
            return Response(
                {"detail": "No pending case found."},
                status=status.HTTP_202_ACCEPTED,
            )

        from tasp.tasks import reconcile_case
        for case_id in case_ids:
            reconcile_case.delay(case_id)
            logger.info(
                "Queued cortex update for case=%s job=%s", case_id, job_id
            )

        return Response(
            {"detail": f"Queued update for {len(case_ids)} case(s)."},
            status=status.HTTP_202_ACCEPTED,
        )
