from celery import shared_task
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)

_RETRY = dict(max_retries=2, acks_late=True)  # 1 initial + 2 retries = MAX_ATTEMPTS


@shared_task(bind=True, **_RETRY)
def deliver_event(self, connector_name: str, event_name: str, payload: dict):
    from connectors.delivery import RetryableDeliveryError, deliver_now
    try:
        deliver_now(connector_name, event_name, payload,
                    attempt=self.request.retries + 1)
    except RetryableDeliveryError as exc:
        raise self.retry(exc=exc, countdown=30 * 2 ** self.request.retries)


@shared_task(bind=True, **_RETRY)
def run_connector_sync(self, connector_name: str):
    from connectors.delivery import RetryableDeliveryError, run_sync_now
    try:
        run_sync_now(connector_name, attempt=self.request.retries + 1)
    except RetryableDeliveryError as exc:
        raise self.retry(exc=exc, countdown=60 * 2 ** self.request.retries)
