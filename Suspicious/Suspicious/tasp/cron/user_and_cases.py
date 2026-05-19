import logging
from django.contrib.auth.models import User
from django.core.cache import cache
from django.db.models import Exists, OuterRef
from case_handler.models import Case
from cortex_job.cortex_utils.cortex_and_job_management import CortexJobManager
from cortex_job.models import CaseAnalyzerJob
from profiles.profiles_utils.ldap import Ldap

logger = logging.getLogger("tasp.cron.users_cases")
log_cases = logging.getLogger("tasp.cron.update_ongoing_case_jobs")

# Bound work per cron tick. Cases beyond this batch wait for the next tick;
# STALE_JOB_TIMEOUT auto-fails any zombie reports independently.
CRON_BATCH_SIZE = 200

# Per-case Redis lock TTL. Long enough to cover one manage_jobs() call,
# short enough that a crashed worker doesn't strand the lock for hours.
CASE_LOCK_TTL = 120


def sync_user_profiles() -> None:
    """Synchronise user profiles via LDAP.

    Restricted to active users and streamed in chunks so a large user
    table is not pulled into memory at every cron tick, and LDAP is
    not pinged for disabled accounts.
    """
    for user in User.objects.filter(is_active=True).iterator(chunk_size=100):
        try:
            Ldap.create_user(user)
        except Exception:
            logger.exception("Failed to sync user %s", user.pk)


def update_ongoing_case_jobs() -> None:
    """Update of ongoing case jobs.

    Bounded scan: at most CRON_BATCH_SIZE oldest cases per tick. Per-case
    Redis lock (`case_update_lock:<id>`) prevents racing with the webhook
    task `process_cortex_job` on the same case.
    """
    from opentelemetry import trace

    tracer = trace.get_tracer(__name__)
    pending_jobs = CaseAnalyzerJob.objects.filter(
        case_id=OuterRef("pk"),
        status__in=CaseAnalyzerJob.PENDING_STATUSES,
    )
    cases = list(
        Case.objects
        .filter(status="On Going")
        .annotate(has_pending=Exists(pending_jobs))
        .filter(has_pending=True)
        .order_by("creation_date")[:CRON_BATCH_SIZE]
    )
    if not cases:
        log_cases.info("No ongoing cases found.")
        return

    with tracer.start_as_current_span("cron.update_ongoing_case_jobs") as span:
        span.set_attribute("cases.count", len(cases))
        manager = CortexJobManager()
        for case in cases:
            lock_key = f"case_update_lock:{case.id}"
            if not cache.add(lock_key, 1, timeout=CASE_LOCK_TTL):
                # Webhook task or another worker is already updating this case.
                continue
            try:
                with tracer.start_as_current_span("cron.manage_case_jobs") as case_span:
                    case_span.set_attribute("case.id", case.id)
                    manager.manage_jobs(case)
                    case.save()
            except Exception:
                log_cases.exception(
                    "Case %s update failed", getattr(case, "id", "<unknown>")
                )
            finally:
                cache.delete(lock_key)
