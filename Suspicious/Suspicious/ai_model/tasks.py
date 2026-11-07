"""Celery tasks of the retrain (ai_model.retrain). Short tasks only: training runs in the inference
server, so no task outlives the broker's visibility timeout."""
import logging

from celery import shared_task

logger = logging.getLogger(__name__)


@shared_task
def poll_retrain(job_id: str) -> None:
    """One status check; queued again while the job runs (MAX_AGE ends it). The re-queue is in a
    finally, so an error in this run does not end the chain while the job is still running; a
    chain that keeps raising past MAX_AGE + STOP_MARGIN stops and fails the job (class name)."""
    from django.db import DatabaseError
    from django.utils import timezone

    from ai_model import retrain
    from ai_model.models import RetrainJob

    error = "TimedOut"
    try:
        retrain.poll_once(job_id)
    except Exception as exc:
        error = type(exc).__name__
        raise
    finally:
        try:
            job = RetrainJob.objects.filter(job_id=job_id, state=RetrainJob.State.RUNNING).first()
            stale = job is not None and timezone.now() - job.started_at > retrain.MAX_AGE + retrain.STOP_MARGIN
        except DatabaseError:
            job, stale = True, False  # the database is away: ask again, the row decides next time
        if stale:
            retrain.give_up(job, error)
        elif job is not None:
            poll_retrain.apply_async((job_id,), countdown=retrain.poll_countdown())


@shared_task
def maybe_start_retrain() -> None:
    """Daily (beat entry in connectors.apps): a no-op unless retrain_enabled (Ruling E10)."""
    from ai_model import retrain

    retrain.maybe_start()


@shared_task
def sync_server() -> None:
    """Every 300 s (beat entry in connectors.apps): push the registry state to the inference server
    when they differ. A no-op while the connector is disabled or has no usable token or url."""
    from connectors.registry import registry

    from ai_model import ledger, serversync

    if not ledger.enabled():
        return
    try:
        client = registry.instantiate("ai_model")._client()
    except ValueError:
        return
    try:
        serversync.sync(client)
    except serversync.ReloadRefused as exc:
        logger.warning("ai_model server sync refused: %s", type(exc).__name__)
