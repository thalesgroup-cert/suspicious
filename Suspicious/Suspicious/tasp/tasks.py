from celery import shared_task
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)

_RETRY = dict(max_retries=3, acks_late=True)


@shared_task(bind=True, **_RETRY)
def fetch_emails(self):
    from tasp.cron.fetch_emails import fetch_and_process_emails
    try:
        fetch_and_process_emails()
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * 2 ** self.request.retries)


@shared_task(bind=True, **_RETRY)
def sync_cortex(self):
    from tasp.cron.sync_cortex import sync_cortex_analyzers
    try:
        sync_cortex_analyzers()
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * 2 ** self.request.retries)


@shared_task(bind=True, **_RETRY)
def update_ongoing_cases(self):
    from tasp.cron.user_and_cases import update_ongoing_case_jobs
    try:
        update_ongoing_case_jobs()
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * 2 ** self.request.retries)


@shared_task(bind=True, **_RETRY)
def check_challengeable(self):
    from tasp.cron.suspicious import check_challengeable as _check
    try:
        _check()
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * 2 ** self.request.retries)


@shared_task(bind=True, **_RETRY)
def sync_monthly_kpi(self):
    from tasp.cron.kpi import sync_monthly_kpi as _sync
    try:
        _sync()
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * 2 ** self.request.retries)


@shared_task(bind=True, **_RETRY)
def sync_user_profiles(self):
    from tasp.cron.user_and_cases import sync_user_profiles as _sync
    try:
        _sync()
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * 2 ** self.request.retries)


@shared_task(bind=True, **_RETRY)
def delete_old_reports(self):
    from tasp.cron.cleanup import delete_old_analyzer_reports
    try:
        delete_old_analyzer_reports()
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * 2 ** self.request.retries)


@shared_task(bind=True, **_RETRY)
def remove_old_emails(self):
    from tasp.cron.suspicious import remove_old_suspicious_emails
    try:
        remove_old_suspicious_emails()
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * 2 ** self.request.retries)


@shared_task(bind=True, **_RETRY)
def watcher_sync(self):
    from tasp.cron.watcher import run_watcher_sync
    try:
        run_watcher_sync()
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * 2 ** self.request.retries)


@shared_task(bind=True, **_RETRY)
def materialise_dashboard_snapshots(self):
    from tasp.cron.dashboard_snapshot import materialise_dashboard_snapshots as _run
    try:
        _run()
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * 2 ** self.request.retries)


@shared_task(bind=True, **_RETRY)
def process_cortex_webhook_case(self, case_id: int):
    """Update a single On Going case after a Cortex job-completion webhook fires.

    Acquires a Redis lock (`case_update_lock:<id>`) to serialise with the
    cron poll `update_ongoing_case_jobs` and any concurrent webhook tasks
    targeting the same case. If the lock is held, returns early — the
    other holder will finish the update.
    """
    from django.core.cache import cache
    from case_handler.models import Case
    from cortex_job.cortex_utils.cortex_and_job_management import CortexJobManager

    lock_key = f"case_update_lock:{case_id}"
    if not cache.add(lock_key, 1, timeout=120):
        return  # Another worker (cron or webhook) is processing this case
    try:
        case = Case.objects.get(pk=case_id, status="On Going")
        manager = CortexJobManager()
        manager.manage_jobs(case)
        case.save()
    except Case.DoesNotExist:
        return
    except Exception as exc:
        raise self.retry(exc=exc, countdown=30 * 2 ** self.request.retries)
    finally:
        cache.delete(lock_key)


def _case_has_pending_jobs(case_id: int) -> bool:
    """Return True if any CaseAnalyzerJob for this case is still pending."""
    from cortex_job.models import CaseAnalyzerJob
    return CaseAnalyzerJob.objects.filter(
        case_id=case_id, status__in=CaseAnalyzerJob.PENDING_STATUSES
    ).exists()


@shared_task(bind=True, **_RETRY)
def process_cortex_job(self, case_id: int, job_id: str):
    """Sync one (case, cortex_job) pair after the webhook fires.

    Acquires a per-case Redis lock to serialise with the cron poll
    `update_ongoing_case_jobs` and other concurrent webhook tasks on the
    same case. Idempotent: the status precheck drops re-deliveries of an
    already-finalised job.

    When this update transitions the case's last pending CAJ to a
    non-pending state, `finalise_case` is invoked to compute the final
    description, status, and CortexAnalyzerReports.get_report.
    """
    from django.core.cache import cache
    from cortex_job.models import CaseAnalyzerJob
    from cortex_job.cortex_utils.cortex_and_job_management import CortexJobManager

    lock_key = f"case_update_lock:{case_id}"
    if not cache.add(lock_key, 1, timeout=120):
        return  # Cron or another webhook task is currently updating this case
    try:
        try:
            caj = CaseAnalyzerJob.objects.select_related(
                "case", "analyzer_report"
            ).get(case_id=case_id, cortex_job_id=job_id)
        except CaseAnalyzerJob.DoesNotExist:
            logger.warning(
                "CaseAnalyzerJob missing (case=%s job=%s)", case_id, job_id
            )
            return

        if caj.status not in CaseAnalyzerJob.PENDING_STATUSES:
            # Already updated by a prior webhook delivery or by the cron.
            return

        manager = CortexJobManager()
        manager.update_single_job(caj)

        if not _case_has_pending_jobs(caj.case_id):
            manager.finalise_case(caj.case)
    except Exception as exc:
        raise self.retry(exc=exc, countdown=30 * 2 ** self.request.retries)
    finally:
        cache.delete(lock_key)
