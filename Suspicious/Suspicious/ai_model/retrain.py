"""Retrain orchestration (Plan E, Task 8b): export the ledger, hand the inference server presigned
URLs through POST /v2/train, poll GET /v2/train/{job_id} with short Celery tasks
(ai_model.tasks.poll_retrain) and register a succeeded job as a `candidate` through the registry.
Nothing here activates or reloads a version (Plan F promotes).

A RetrainJob row is written before the server is called; a failed, cancelled, timed-out or
half-uploaded job registers nothing and its bundle prefix and dataset are deleted. Presigned URLs
go into the request body only: never logged, stored or printed. Errors are stored as class names,
or, for a job the server failed, as the server's own short reason filtered by server_error."""
import dataclasses
import logging
import re
import secrets
from datetime import timedelta

from django.db import IntegrityError, transaction
from django.utils import timezone

from . import ledger, registry
from .campaign_profile import current_profile
from .export import ExportRefused, export_ledger
from .models import ModelVersion, RetrainJob
from .training_data import TRAINING_PREPROCESSING

logger = logging.getLogger("ai_model.retrain")
J = RetrainJob.State

POLL_SECONDS = 30
MAX_AGE = timedelta(hours=6)  # a job still running after this is cancelled and failed
# A poll chain that keeps raising stops this long after MAX_AGE and fails the job itself.
STOP_MARGIN = timedelta(minutes=30)
BACKOFF = timedelta(days=7)  # after a failed or refused scheduled retrain
# The PUT URLs are used when training ends, so they must outlive the server's wall limit
# (AI_TRAIN_MAX_SECONDS, 4 h by default). One key per job and the manifest hash pinned in the
# registry bound what a leaked URL can do: overwrite an unregistered key, which reload refuses.
UPLOAD_EXPIRY = timedelta(hours=4, minutes=15)
SEED, REPEATS = 0, 3  # fixed: the same ledger digest and seed give the same metrics
ENCODER_ID = "sentence-transformers/paraphrase-multilingual-mpnet-base-v2"
TRAINER_REVISION = "plan-e-candidate-v1"
GATE_KEYS = ("checks", "candidate", "baseline", "campaign", "tier_cutoffs")


_UNSAFE = re.compile(r"[^A-Za-z0-9 _.:,()/=-]")
ERROR_MAX = 200  # RetrainJob.error


def server_error(text) -> str:
    """The server's `error` of a failed job, kept for the operator: only [A-Za-z0-9 _.:,()/=-],
    at most ERROR_MAX characters; anything holding a URL ("://") or a query ("?") is dropped whole.
    The server's reasons name fields, heads and classes (e.g. the head floor), never mail text."""
    if not isinstance(text, str) or "://" in text or "?" in text:
        return "TrainingFailed"
    return _UNSAFE.sub("", text)[:ERROR_MAX].strip() or "TrainingFailed"


class RetrainRefused(Exception):
    """The retrain did not start; the message says why (no URL, no mail text). cause: the class
    name of an unexpected error behind it, if any."""

    def __init__(self, message: str, cause: str = ""):
        super().__init__(message)
        self.cause = cause


class JobRunning(RetrainRefused):
    """Another retrain job holds the running slot."""


class IncompleteUpload(Exception):
    pass


def _connector(check_enabled=True):
    from connectors.registry import registry as connectors
    if check_enabled and not ledger.enabled():
        raise RetrainRefused("the ai_model connector is disabled")
    return connectors.instantiate("ai_model")


def running_job():
    return RetrainJob.objects.filter(state=J.RUNNING).first()


def _parent(user):
    return (ModelVersion.objects.filter(status=ModelVersion.Status.ACTIVE).first()
            or registry.ensure_version_zero(user))


def _new_ids(now):
    return f"rt-{now:%Y%m%d%H%M%S}-{secrets.token_hex(3)}", f"v{now:%Y%m%d%H%M%S}"


def start_retrain(user=None, trigger=ModelVersion.Trigger.MANUAL) -> RetrainJob:
    """Start one training job. RetrainRefused when the connector is disabled, a job is running,
    the export refuses (its message passes through) or the server refuses the request."""
    connector = _connector()
    job = running_job()
    if job is not None:
        try:
            state = poll_once(job.job_id)  # finishes a stale job first
        except Exception as exc:  # noqa: BLE001: the class only; poll_retrain fails it after MAX_AGE
            raise JobRunning(f"retrain job {job.job_id} could not be checked: {type(exc).__name__}") from None
        if state == J.RUNNING:
            raise JobRunning(f"retrain job {job.job_id} is running")
    now = timezone.now()
    job_id, version_id = _new_ids(now)
    prefix = registry.bundle_prefix_for(version_id, job_id)
    try:
        exported = export_ledger(job_id)  # creates the dataset bucket
    except ExportRefused as exc:
        raise RetrainRefused(str(exc)) from None
    except Exception as exc:  # noqa: BLE001: the store (or a bug): drop what may have been put
        _delete_dataset(job_id)
        name = type(exc).__name__
        raise RetrainRefused(f"could not export the ledger: {name}", cause=name) from None
    try:
        registry.ensure_bucket()
        store = registry.get_store()
        bucket, _, key = prefix.partition("/")
        bundle_urls = {n: store.presign_put(bucket, key + n, UPLOAD_EXPIRY) for n in registry.BUNDLE_FILE_NAMES}
        parent = _parent(user)
    except Exception as exc:  # noqa: BLE001: no job yet: drop the exported dataset, say the class
        _delete_dataset(job_id)
        name = type(exc).__name__
        raise RetrainRefused(f"could not prepare the training job: {name}", cause=name) from None
    params = {
        "version_id": version_id, "seed": SEED, "repeats": REPEATS,
        "baseline": "legacy" if parent.version_id == "v0" else "candidate",
        "preprocessing_version": TRAINING_PREPROCESSING, "parent_version": parent.version_id,
        "ledger_digest": exported.ledger_digest, "campaign_refs_digest": exported.campaign_refs_digest,
        "encoder_id": ENCODER_ID, "trainer_revision": TRAINER_REVISION,
        "campaign_profile": dataclasses.asdict(current_profile()),
    }
    try:
        with transaction.atomic():
            job = RetrainJob.objects.create(
                job_id=job_id, target_version=version_id, state=J.RUNNING, running_slot=1, prefix=prefix,
                params=params, rows=exported.rows, excluded_rows=exported.excluded, parent=parent, trigger=trigger, requested_by=user,
                started_at=now)
    except IntegrityError:  # another start won the running slot
        _delete_dataset(job_id)
        raise JobRunning("another retrain job is running") from None
    from .tasks import poll_retrain
    # Queued before the call: if this process dies during it, the poll still settles the job.
    poll_retrain.apply_async((job_id,), countdown=poll_countdown())
    from connectors.contrib.ai_model.client import ServerBusy
    from connectors.providers import ProviderUnavailable
    body = {"job_id": job_id, "dataset_url": exported.url, "bundle_urls": bundle_urls, "params": params}
    try:
        connector._client().train(body)
    except ServerBusy:
        _finish(job, J.FAILED, "ServerBusy")
        raise RetrainRefused("the inference server is running another training job") from None
    except ProviderUnavailable as exc:
        if exc.retryable:  # it may have arrived: the poll finds out (404 fails it)
            return job
        _finish(job, J.FAILED, type(exc).__name__)
        raise RetrainRefused(str(exc)) from None
    except Exception as exc:  # noqa: BLE001: a 4xx (ValueError) or a bug: no job on the server
        _finish(job, J.FAILED, type(exc).__name__)
        raise RetrainRefused(f"the training request failed: {type(exc).__name__}") from None
    return job


def poll_once(job_id: str) -> str:
    """Ask the server once and settle the job if it ended. Returns the job's state after.
    The server's answer comes first: a job it finished is registered even when polled after
    MAX_AGE; MAX_AGE only ends a job that is still running (or that nobody can ask about)."""
    from connectors.contrib.ai_model.client import TrainJobGone, TryLater
    from connectors.providers import ProviderUnavailable

    job = RetrainJob.objects.get(job_id=job_id)
    if job.state != J.RUNNING:
        return job.state
    client, answer = None, None
    try:
        client = _connector(check_enabled=False)._client()  # ValueError: no token or bad url
        answer = client.train_status(job_id)
    except TrainJobGone:  # the server restarted or never got the job
        return _finish(job, J.FAILED, "TrainJobGone").state
    except TryLater:  # 408, 429: ask again later
        pass
    except ProviderUnavailable as exc:
        if not exc.retryable:  # the server job may still run: stop it uploading into a deleted prefix
            _cancel_quietly(client, job_id)
            return _finish(job, J.FAILED, type(exc).__name__).state
    except ValueError:  # a 4xx, or the connector is misconfigured: ask again later
        pass
    state = answer.get("state") if isinstance(answer, dict) else None
    if state == "succeeded":
        return _finish(job, J.SUCCEEDED, report=answer.get("report")).state
    if state == "failed":
        return _finish(job, J.FAILED, server_error(answer.get("error"))).state
    if state == "cancelled":
        return _finish(job, J.CANCELLED).state
    if timezone.now() - job.started_at > MAX_AGE:
        _cancel_quietly(client, job_id)
        return _finish(job, J.FAILED, "TimedOut").state
    return J.RUNNING


def _cancel_quietly(client, job_id) -> None:
    """Best effort (client may be None): the job is failed either way."""
    try:
        client.train_cancel(job_id)
    except Exception as exc:  # noqa: BLE001
        logger.info("Retrain %s: cancel failed: %s", job_id, type(exc).__name__)


def give_up(job, error: str) -> None:
    """Fail a job whose poll chain keeps raising, past MAX_AGE + STOP_MARGIN (poll_retrain)."""
    try:
        _finish(job, J.FAILED, error)
    except Exception as exc:  # noqa: BLE001: the chain stops either way; the class is logged
        logger.warning("Retrain %s: could not fail the job: %s", job.job_id, type(exc).__name__)


def poll_countdown() -> int:
    """Seconds before the next poll: at least POLL_SECONDS, and longer than the client timeout, so
    a slow POST /v2/train is not answered 404 by a poll that overtook it."""
    try:
        return max(POLL_SECONDS, int(_connector(check_enabled=False)._client().timeout) + 5)
    except Exception:  # noqa: BLE001: a misconfigured connector still gets polled
        return POLL_SECONDS


def _manifest(job, report):
    if set(report["uploaded"]) != set(registry.BUNDLE_FILE_NAMES):
        raise IncompleteUpload
    summary = {k: v for k, v in job.params.items() if k != "campaign_profile"}
    # encoder_hash: the server's digest of its encoder files (it is not sent in the params)
    summary.update(job_id=job.job_id, rows=job.rows, excluded_rows=job.excluded_rows, eligible=report["eligible"] is True,
                   encoder_hash=report.get("encoder_hash"),
                   gate={k: report.get(k) for k in GATE_KEYS})
    return summary, report["manifest_sha256"]


def _finish(job, state, error="", report=None):
    """Settle a running job once (a locking read: a redelivered poll or --wait does nothing more).
    A succeeded job becomes a candidate; anything that stops that fails the job instead."""
    with transaction.atomic():
        locked = RetrainJob.objects.select_for_update().get(pk=job.pk)
        if locked.state != J.RUNNING:
            return locked
        if state == J.SUCCEEDED:
            try:
                manifest, sha = _manifest(locked, report)
                with transaction.atomic():
                    locked.version = registry.create_candidate(
                        locked.target_version, locked.prefix, manifest, sha, locked.params["campaign_profile"],
                        locked.trigger, locked.requested_by, locked.job_id, parent=locked.parent)
            except (registry.RegistryError, IncompleteUpload, KeyError, TypeError, AttributeError,
                    IntegrityError) as exc:
                state, error = J.FAILED, type(exc).__name__
        locked.state, locked.error, locked.running_slot = state, error[:ERROR_MAX], None
        locked.finished_at = timezone.now()
        locked.save(update_fields=["state", "error", "running_slot", "finished_at", "version"])
    if state != J.SUCCEEDED:
        _delete_bundle(locked)
    _delete_dataset(locked.job_id)
    logger.info("Retrain %s: %s %s", locked.job_id, state, error)
    return locked


def _delete_under(bucket, key):
    """Delete every object whose key starts with key. A key of fewer than 3 characters, or of
    slashes only, is refused (it would reach other jobs' objects)."""
    if len(key) < 3 or not key.strip("/"):
        logger.warning("Retrain cleanup refused a short key")
        return
    store = registry.get_store()
    try:
        if store.bucket_exists(bucket):
            store.delete_many(bucket, [o.name for o in store.list(bucket, key)])
    except Exception as exc:  # noqa: BLE001: the job is settled; leftovers are unregistered
        logger.warning("Retrain cleanup failed: %s", type(exc).__name__)


def _delete_bundle(job):
    """The job's bundle files, at the prefix derived again from its ids (not the stored prefix)."""
    try:
        prefix = registry.bundle_prefix_for(job.target_version, job.job_id)
    except registry.RegistryError:
        logger.warning("Retrain cleanup refused a job with malformed ids")
        return
    bucket, _, key = prefix.partition("/")
    _delete_under(bucket, key)


def _delete_dataset(job_id):
    _delete_under(registry.DATASET_BUCKET, registry.dataset_key_for(job_id))


def cancel_retrain():
    """Ask the server to cancel the running job; the poll records the outcome. None if no job."""
    job = running_job()
    if job is None:
        return None
    from connectors.contrib.ai_model.client import TrainJobGone
    try:
        _connector(check_enabled=False)._client().train_cancel(job.job_id)
    except TrainJobGone:
        _finish(job, J.FAILED, "TrainJobGone")
    return job


def maybe_start():
    """The daily check: start a retrain when `retrain_enabled` is true, no job runs and the newest
    candidate, shadow, active or previous version is older than `retrain_interval_days`.
    Backoff: a scheduled job that failed (or a scheduled start that was refused, recorded as a
    failed job with error "Refused") within BACKOFF stops the check until it is older."""
    if not ledger.enabled():
        return None
    config = _connector().config
    if config.get("retrain_enabled") is not True:
        return None
    try:
        days = max(int(config.get("retrain_interval_days", 30)), 0)
    except (TypeError, ValueError):
        days = 30
    S = ModelVersion.Status
    newest = (ModelVersion.objects.filter(status__in=(S.CANDIDATE, S.SHADOW, S.ACTIVE, S.PREVIOUS))
              .order_by("-created_at").first())
    if newest and newest.created_at > timezone.now() - timedelta(days=days):
        return None
    now = timezone.now()
    if RetrainJob.objects.filter(trigger=ModelVersion.Trigger.SCHEDULE, state=J.FAILED,
                                 started_at__gte=now - BACKOFF).exists():
        return None
    try:
        return start_retrain(trigger=ModelVersion.Trigger.SCHEDULE)
    except JobRunning:
        return None
    except RetrainRefused as exc:
        logger.info("Scheduled retrain not started: %s", exc)
        job_id, version_id = _new_ids(now)
        RetrainJob.objects.create(
            job_id=job_id, target_version=version_id, state=J.FAILED, running_slot=None,
            prefix=registry.bundle_prefix_for(version_id, job_id), trigger=ModelVersion.Trigger.SCHEDULE,
            started_at=now, finished_at=now, error=f"Refused: {exc.cause}" if exc.cause else "Refused")
        return None
