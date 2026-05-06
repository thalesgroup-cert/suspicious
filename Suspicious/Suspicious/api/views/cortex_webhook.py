"""POST /api/cortex/webhook/ — Cortex job-completion callback.

Cortex calls this endpoint when a job finishes (Success or Failure).
We look up which On Going case owns the job and dispatch a targeted
Celery task instead of waiting for the 60-second cron poll.

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
from django.db.models import Q
from rest_framework import status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

logger = logging.getLogger(__name__)

# How long to remember a processed jobId. Cortex retries within minutes;
# 1 hour is comfortably above the upper bound of legitimate retry windows.
_WEBHOOK_DEDUP_TTL = 3600


def _find_case_ids_for_job(job_id: str) -> list[int]:
    """Return IDs of On Going cases that contain the artifact for this job."""
    from cortex_job.models import AnalyzerReport
    from case_handler.models import Case

    try:
        report = (
            AnalyzerReport.objects
            .filter(cortex_job_id=job_id)
            .order_by("-creation_date")
            .first()
        )
    except Exception:
        logger.exception("DB error looking up AnalyzerReport for job %s", job_id)
        return []

    if report is None:
        return []

    q = Q()
    # Direct file/IOC linkage
    if report.file_id:
        q |= Q(fileOrMail__file_id=report.file_id)
    if report.url_id:
        q |= Q(nonFileIocs__url_id=report.url_id)
    if report.ip_id:
        q |= Q(nonFileIocs__ip_id=report.ip_id)
    if report.hash_id:
        q |= Q(nonFileIocs__hash_id=report.hash_id)
    # Mail body/header linkage
    if report.mail_body_id:
        q |= Q(fileOrMail__mail__mail_body_id=report.mail_body_id)
    if report.mail_header_id:
        q |= Q(fileOrMail__mail__mail_header_id=report.mail_header_id)

    if not q.children:
        logger.warning("AnalyzerReport %s has no recognised artifact FK; cannot map to case", report.pk)
        return []

    return list(
        Case.objects.filter(q, status="On Going")
        .values_list("id", flat=True)
        .distinct()
    )


class CortexWebhookView(APIView):
    authentication_classes = []  # Cortex uses a shared secret, not user sessions
    permission_classes = []

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
        case_ids = _find_case_ids_for_job(job_id)
        if not case_ids:
            # Job may belong to an artifact inside a mail (complex traversal) —
            # the 60-second cron fallback will catch it.
            logger.info("No On Going case found for jobId=%s; cron fallback will handle it", job_id)
            return Response({"detail": "No matching case found; cron fallback active."}, status=status.HTTP_202_ACCEPTED)

        from tasp.tasks import process_cortex_webhook_case
        for case_id in case_ids:
            process_cortex_webhook_case.delay(case_id)
            logger.info("Queued cortex update for case_id=%s (jobId=%s)", case_id, job_id)

        return Response({"detail": f"Queued update for {len(case_ids)} case(s)."}, status=status.HTTP_202_ACCEPTED)
