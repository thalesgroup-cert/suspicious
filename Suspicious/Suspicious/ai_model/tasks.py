"""Celery tasks of the retrain (ai_model.retrain). Short tasks only: training runs in the inference
server, so no task outlives the broker's visibility timeout."""
from celery import shared_task


@shared_task
def poll_retrain(job_id: str) -> None:
    """One status check; queued again every POLL_SECONDS while the job runs (MAX_AGE ends it)."""
    from ai_model import retrain

    if retrain.poll_once(job_id) == retrain.J.RUNNING:
        poll_retrain.apply_async((job_id,), countdown=retrain.POLL_SECONDS)


@shared_task
def maybe_start_retrain() -> None:
    """Daily (beat entry in connectors.apps): a no-op unless retrain_enabled (Ruling E10)."""
    from ai_model import retrain

    retrain.maybe_start()
