from celery import shared_task
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)

_RETRY = dict(max_retries=2, acks_late=True)


@shared_task(bind=True, **_RETRY)
def deliver_event(self, connector_name: str, event_name: str, payload: dict, deferrals: int = 0):
    from connectors.delivery import (
        MAX_ATTEMPTS, MAX_DEFERRALS, DeliverLater, RetryableDeliveryError, deliver_now,
    )
    # Deferrals are not attempts: only the retries beyond them count.
    attempt = max(1, self.request.retries - deferrals + 1)
    budget = MAX_DEFERRALS + MAX_ATTEMPTS
    try:
        deliver_now(connector_name, event_name, payload, attempt=attempt, deferrals=deferrals)
    except DeliverLater as later:
        raise self.retry(exc=later, countdown=later.countdown, max_retries=budget,
                         kwargs={"deferrals": deferrals + 1})
    except RetryableDeliveryError as exc:
        raise self.retry(exc=exc, countdown=30 * 2 ** (attempt - 1), max_retries=budget,
                         kwargs={"deferrals": deferrals})


@shared_task(bind=True, **_RETRY)
def run_connector_sync(self, connector_name: str):
    from connectors.delivery import RetryableDeliveryError, run_sync_now
    try:
        run_sync_now(connector_name, attempt=self.request.retries + 1)
    except RetryableDeliveryError as exc:
        raise self.retry(exc=exc, countdown=60 * 2 ** self.request.retries)
