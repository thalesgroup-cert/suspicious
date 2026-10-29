import threading
import uuid
from contextlib import contextmanager

from celery import shared_task
from celery.utils.log import get_task_logger
from django.core.cache import cache

from case_handler.lifecycle import LifecycleState, transition
from case_handler.models import Case, Result
from cortex_job.cortex_utils.reconciliation import reconcile_case_core

logger = get_task_logger(__name__)

_RETRY = dict(max_retries=3, acks_late=True)

CASE_LOCK_TTL = 120


_FETCH_EMAILS_LOCK_KEY = "fetch_emails_lock"
# A run renews the lock while it lives, so the TTL only has to outlast a missed beat:
# a worker killed mid-run (SIGKILL, OOM) frees the lock within one TTL, not the old 30 minutes.
_FETCH_EMAILS_LOCK_TTL = 120
_FETCH_EMAILS_HEARTBEAT = 30


@contextmanager
def _fetch_emails_lock():
    """Yield True when this run owns the lock, False when another run holds it."""
    token = uuid.uuid4().hex
    if not cache.add(_FETCH_EMAILS_LOCK_KEY, token, timeout=_FETCH_EMAILS_LOCK_TTL):
        yield False
        return
    stop = threading.Event()

    def beat():
        while not stop.wait(_FETCH_EMAILS_HEARTBEAT):
            try:
                if cache.get(_FETCH_EMAILS_LOCK_KEY) == token:
                    cache.touch(_FETCH_EMAILS_LOCK_KEY, _FETCH_EMAILS_LOCK_TTL)
            except Exception:
                logger.warning("fetch_emails: lock heartbeat failed", exc_info=True)

    threading.Thread(target=beat, name="fetch-emails-heartbeat", daemon=True).start()
    try:
        yield True
    finally:
        stop.set()
        # ponytail: get-then-delete is not atomic; a lock lost to expiry and retaken in this window is rare
        if cache.get(_FETCH_EMAILS_LOCK_KEY) == token:
            cache.delete(_FETCH_EMAILS_LOCK_KEY)


@shared_task(bind=True, **_RETRY)
def fetch_emails(self):
    from tasp.cron.fetch_emails import fetch_and_process_emails
    with _fetch_emails_lock() as owned:
        if not owned:
            logger.info("fetch_emails: previous run still in flight, skipping this tick")
            return
        try:
            fetch_and_process_emails()
        except Exception as exc:
            raise self.retry(exc=exc, countdown=60 * 2 ** self.request.retries)


@shared_task(bind=True, max_retries=5, acks_late=True)
def push_challenge_to_thehive(self, case_id: int, mail_header: str):
    """Off the request path: TheHive being down must not stall the challenge, and the
    alert is retried (1, 2, 4, 8, 16 minutes) instead of being lost."""
    from tasp.services.challenge import send_challenge_to_thehive
    case = Case.objects.filter(id=case_id).first()
    if case is None:
        return
    try:
        send_challenge_to_thehive(case, mail_header)
    except Exception as exc:
        logger.warning("TheHive challenge push for case %s failed (attempt %s): %s",
                       case_id, self.request.retries + 1, exc)
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
    from tasp.cron.user_and_cases import update_ongoing_cases as _update_ongoing_cases
    try:
        _update_ongoing_cases()
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
def purge_old_mail_previews(self, older_than_days: int = 90):
    """Age-only bucket sweep; see mail_feeder.utils.email_preview.retention
    for why this never touches Mail.preview_object_key. Oversized-but-recent
    outliers (the actual disk-usage incident) are a manual
    `purge_mail_previews --min-size-mb` call, not part of the automated
    sweep: an automatic size cutoff could delete a legitimately long
    email's preview the same day it was rendered.
    """
    from mail_feeder.utils.email_preview.retention import purge_mail_previews
    try:
        purge_mail_previews(older_than_days=older_than_days)
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

    try:
        cutoff = timezone.now() - timedelta(seconds=STALE_JOB_TIMEOUT_SECONDS)
        n = CaseAnalyzerJob.objects.filter(
            status__in=CaseAnalyzerJob.PENDING_STATUSES,
            created_at__lt=cutoff,
        ).update(status=CaseAnalyzerJob.STATUS_FAILURE, completed_at=timezone.now())
        if n:
            logger.warning(
                "fail_stale_jobs: marked %d CaseAnalyzerJob rows as Failure", n
            )
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * 2 ** self.request.retries)


_PREVIEW_COOLDOWN_TTL = 24 * 3600  # a preview that cannot be rendered is not retried for a day


def _preview_cooldown_key(mail_id: int) -> str:
    return f"preview_render_cooldown:{mail_id}"


@shared_task(bind=True, **_RETRY)
def render_mail_preview(self, mail_id: int):
    """Render + store one mail's .eml->PNG preview from its MinIO archive.

    Sourced from the durable MinIO archive (not the ingestion workdir), so
    it runs on the worker pool independent of the request that created the
    mail. No-op when the mail or its fetchable archive is gone; retries on
    transient MinIO / render errors.

    A mail that ends "skipped" (no fetchable .eml) or exhausts its retries
    gets a cooldown key: its preview_object_key stays empty, so without it
    the sweeper would re-pick the same rows every run and re-render them
    (wkhtmltoimage, hundreds of MB each) indefinitely.
    """
    from mail_feeder.models import Mail
    from mail_feeder.utils.email_preview.eml2png_renderer import Eml2PngRenderer
    from mail_feeder.utils.email_preview.preview_jobs import (
        build_storage_client,
        fetch_eml_bytes,
        regenerate_mail_preview,
    )

    if cache.get(_preview_cooldown_key(mail_id)):
        logger.info("render_mail_preview: mail %s in cooldown, skipping", mail_id)
        return

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
        if outcome == "skipped":
            cache.set(_preview_cooldown_key(mail_id), 1, _PREVIEW_COOLDOWN_TTL)
        logger.info("render_mail_preview: mail %s -> %s", mail_id, outcome)
    except Exception as exc:
        if self.request.retries >= self.max_retries:
            cache.set(_preview_cooldown_key(mail_id), 1, _PREVIEW_COOLDOWN_TTL)
            logger.error(
                "render_mail_preview: mail %s failed %d times, cooling down %ds",
                mail_id, self.request.retries + 1, _PREVIEW_COOLDOWN_TTL,
            )
        raise self.retry(exc=exc, countdown=30 * 2 ** self.request.retries)


@shared_task(bind=True, **_RETRY)
def sweep_missing_mail_previews(self, limit: int = 200):
    """Self-healing backfill of missing mail previews.

    Replaces the manual `regenerate_mail_previews` command for the steady
    state: each run enqueues `render_mail_preview` for rows that (a) have
    no preview yet and (b) own a MinIO archive with a non-empty bucket
    (i.e. are fetchable). Bucket-less submissions are excluded so they are
    not re-enqueued every run. Rows in render cooldown (see
    `render_mail_preview`) are skipped, so permanently unrenderable mails
    cannot occupy the head of the pk-ordered queue and starve newer ones.
    """
    from mail_feeder.models import Mail

    try:
        candidates = list(
            Mail.objects.filter(
                preview_object_key="",
                mail_archive__bucket_name__gt="",
            )
            .order_by("pk")
            .values_list("pk", flat=True)
            .distinct()
        )
        pks = []
        for start in range(0, len(candidates), 500):
            chunk = candidates[start:start + 500]
            cooling = cache.get_many([_preview_cooldown_key(pk) for pk in chunk])
            pks.extend(pk for pk in chunk if _preview_cooldown_key(pk) not in cooling)
            if len(pks) >= limit:
                break
        pks = pks[:limit]
        for pk in pks:
            render_mail_preview.delay(pk)
        if pks:
            logger.info(
                "sweep_missing_mail_previews: enqueued %d preview render(s)", len(pks)
            )
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * 2 ** self.request.retries)


# Intent labels that are not a model: the value travels as-is (a file path the worker
# shares with the web container), or the intent is the mail archive for the AI analyzer.
PATH_INTENT = "__path__"
AI_ARCHIVE_INTENT = "ai_archive"


@shared_task(bind=True, **_RETRY)
def dispatch_case_analysis(self, case_id: int, intents: list, use_sender_domain: bool = False):
    """Launch Cortex analyzers for a just-submitted case in the background.

    Moved off the request/response path: the synchronous Cortex round-trips
    (analyzer lookup + run_by_name per matched analyzer) used to run inline
    in the submit view, so users waited on Cortex for every submission.
    `intents` is a JSON-safe list of (app_label.model, pk, data_type) triples
    (model instances aren't JSON-serializable, so callers resolve+serialize
    them before enqueueing); we re-fetch the objects here. A `PATH_INTENT` entry
    carries its value in the pk slot, and an `AI_ARCHIVE_INTENT` entry runs the AI
    analyzer after every other job. `use_sender_domain` lets the URL planner see the
    mail's sender, as the inline mail path did.
    """
    from django.apps import apps
    from django.utils import timezone
    from cortex_job.cortex_utils.cortex_and_job_management import CortexJob
    from url_process.url_utils.url_planner import filter_dispatch_intents

    case = Case.objects.filter(id=case_id).first()
    if case is None:
        logger.warning("dispatch_case_analysis: case %s no longer exists", case_id)
        return

    resolved, ai_archives = [], []
    for label, pk, data_type in intents:
        try:
            value = pk if label == PATH_INTENT else apps.get_model(label).objects.get(pk=pk)
        except Exception:
            logger.exception("dispatch_case_analysis: failed to resolve %s pk=%s", label, pk)
            continue
        (ai_archives if data_type == AI_ARCHIVE_INTENT else resolved).append((value, data_type))

    if intents and case.lifecycle_state == LifecycleState.FINALIZED:
        # Closed on "no jobs" before this task ran (a worker down past the grace, or an
        # earlier empty dispatch): reopen it so the jobs launched now are scored instead of
        # stranded behind a finished case. A redo reopens its own case before dispatching.
        transition(case, LifecycleState.ANALYZING)
        case.results = Result.INCONCLUSIVE
        case.score = case.final_score = 0
        case.save(update_fields=["results", "score", "final_score"])

    sender_domain = None
    if use_sender_domain:
        from mail_feeder.job_handler.artifacts.artifacts import _sender_domain_for_case
        sender_domain = _sender_domain_for_case(case)
    filtered = filter_dispatch_intents(resolved, sender_domain=sender_domain)
    cortex = CortexJob()
    for value, data_type in filtered:
        try:
            cortex.launch_cortex_jobs(value=value, data_type=data_type, case=case)
        except Exception:
            logger.exception(
                "Failed to launch Cortex jobs (case=%s data_type=%s)", case_id, data_type
            )
    for archive, _data_type in ai_archives:
        try:
            cortex.launch_cortex_ai_jobs(archive, "file", case=case)
        except Exception:
            logger.exception("Failed to launch the Cortex AI job (case=%s)", case_id)

    case.dispatched_at = timezone.now()
    case.save(update_fields=["dispatched_at"])
    reconcile_case.delay(case_id)


@shared_task(bind=True)
def reconcile_case(self, case_id: int):
    """Single finalise entrypoint: sync ledger + advance the state machine."""
    lock_key = f"case_update_lock:{case_id}"
    if not cache.add(lock_key, 1, timeout=CASE_LOCK_TTL):
        return
    try:
        case = Case.objects.filter(id=case_id).first()
        if case is None:
            return
        reconcile_case_core(case)
    except Exception:
        logger.exception("reconcile_case failed for case %s", case_id)
    finally:
        cache.delete(lock_key)
