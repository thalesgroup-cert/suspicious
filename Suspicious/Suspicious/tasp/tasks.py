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
def fail_stale_jobs(self):
    """Auto-fail CaseAnalyzerJob rows pending beyond STALE_JOB_TIMEOUT.

    Mirrors the existing AnalyzerReport stale-rescue but operates on the
    ledger so per-case visibility is preserved even when AnalyzerReport
    rows have been GC'd by delete_old_reports.
    """
    from datetime import timedelta
    from django.utils import timezone
    from cortex_job.models import CaseAnalyzerJob
    from cortex_job.cortex_utils.cortex_and_job_management import (
        STALE_JOB_TIMEOUT_SECONDS,
    )

    cutoff = timezone.now() - timedelta(seconds=STALE_JOB_TIMEOUT_SECONDS)
    n = CaseAnalyzerJob.objects.filter(
        status__in=CaseAnalyzerJob.PENDING_STATUSES,
        created_at__lt=cutoff,
    ).update(status=CaseAnalyzerJob.STATUS_FAILURE, completed_at=timezone.now())
    if n:
        logger.warning(
            "fail_stale_jobs: marked %d CaseAnalyzerJob rows as Failure", n
        )


@shared_task(bind=True, **_RETRY)
def render_mail_preview(self, mail_id: int):
    """Render + store one mail's .eml->PNG preview from its MinIO archive.

    Sourced from the durable MinIO archive (not the ingestion workdir), so
    it runs on the worker pool independent of the request that created the
    mail. No-op when the mail or its fetchable archive is gone; retries on
    transient MinIO / render errors.
    """
    from mail_feeder.models import Mail
    from mail_feeder.utils.email_preview.eml2png_renderer import Eml2PngRenderer
    from mail_feeder.utils.email_preview.preview_jobs import (
        build_storage_client,
        fetch_eml_bytes,
        regenerate_mail_preview,
    )

    try:
        mail = Mail.objects.filter(pk=mail_id).first()
        if mail is None:
            logger.warning("render_mail_preview: mail %s not found", mail_id)
            return

        storage = build_storage_client()
        renderer = Eml2PngRenderer()
        outcome = regenerate_mail_preview(
            mail,
            fetch_eml=lambda archive: fetch_eml_bytes(storage, archive.bucket_name),
            renderer=renderer,
        )
        if outcome == "failed":
            raise RuntimeError(f"preview render failed for mail {mail_id}")
        logger.info("render_mail_preview: mail %s -> %s", mail_id, outcome)
    except Exception as exc:
        raise self.retry(exc=exc, countdown=30 * 2 ** self.request.retries)


@shared_task(bind=True, **_RETRY)
def sweep_missing_mail_previews(self, limit: int = 200):
    """Self-healing backfill of missing mail previews.

    Replaces the manual `regenerate_mail_previews` command for the steady
    state: each run enqueues `render_mail_preview` for rows that (a) have
    no preview yet and (b) own a MinIO archive with a non-empty bucket
    (i.e. are fetchable). Bucket-less submissions are excluded so they are
    not re-enqueued every run.
    """
    from mail_feeder.models import Mail

    try:
        pks = list(
            Mail.objects.filter(
                preview_object_key="",
                mail_archive__bucket_name__gt="",
            )
            .order_by("pk")
            .values_list("pk", flat=True)
            .distinct()[:limit]
        )
        for pk in pks:
            render_mail_preview.delay(pk)
        if pks:
            logger.info(
                "sweep_missing_mail_previews: enqueued %d preview render(s)", len(pks)
            )
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * 2 ** self.request.retries)


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
