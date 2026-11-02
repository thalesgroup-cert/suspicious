"""Celery tasks of the retrain (ai_model.retrain). Short tasks only: training runs in the inference
server, so no task outlives the broker's visibility timeout."""
from celery import shared_task


@shared_task
def poll_retrain(job_id: str) -> None:
    """One status check; queued again while the job runs (MAX_AGE ends it). The re-queue is in a
    finally, so an error in this run does not end the chain while the job is still running."""
    from django.db import DatabaseError

    from ai_model import retrain
    from ai_model.models import RetrainJob

    try:
        retrain.poll_once(job_id)
    finally:
        try:
            running = RetrainJob.objects.filter(job_id=job_id, state=RetrainJob.State.RUNNING).exists()
        except DatabaseError:
            running = True  # the database is away: ask again, the row decides next time
        if running:
            poll_retrain.apply_async((job_id,), countdown=retrain.poll_countdown())


@shared_task
def maybe_start_retrain() -> None:
    """Daily (beat entry in connectors.apps): a no-op unless retrain_enabled (Ruling E10)."""
    from ai_model import retrain

    retrain.maybe_start()
