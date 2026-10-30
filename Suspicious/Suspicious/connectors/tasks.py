import random
import time

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


@shared_task(bind=True, acks_late=True, reject_on_worker_lost=True, max_retries=2)
def run_provider_analysis(self, case_id: int, kind: str, job_id: int):
    """Run the enabled ``kind`` provider for one case and close its ledger row.
    Only a retryable ProviderUnavailable is retried; anything else (an open
    breaker, a disabled provider, a 4xx) finishes the row as failure at once."""
    from common.http_client import get_breaker
    from connectors.providers import (
        ProviderUnavailable, finish_provider_analysis, provider_connector,
    )
    from cortex_job.models import CaseAnalyzerJob

    if not CaseAnalyzerJob.objects.filter(
        pk=job_id, status__in=CaseAnalyzerJob.PENDING_STATUSES
    ).exists():
        return  # closed already (redelivery, or fail_stale_jobs got there first)
    started = time.monotonic()
    name, result, error = kind, None, "provider returned no result"
    try:
        connector = provider_connector(kind)
        name = connector.manifest.name
        with get_breaker(name).calling():
            result = connector.analyze(kind, case_id)
    except ProviderUnavailable as exc:
        if exc.retryable and self.request.retries < self.max_retries:
            raise self.retry(
                exc=exc, countdown=5 * 2 ** self.request.retries + random.uniform(0, 3)
            )
        error = str(exc)
    except Exception as exc:  # noqa: BLE001 — connector code is untrusted
        error = f"{type(exc).__name__}: {exc}"
    ledger = dict(attempt=self.request.retries + 1, connector=name,
                  duration_ms=int((time.monotonic() - started) * 1000))
    if result is not None:
        try:
            finish_provider_analysis(job_id, result, **ledger)
            return
        except Exception as exc:  # noqa: BLE001 — a bad result must not strand the case
            error = f"could not store the result: {type(exc).__name__}: {exc}"
    finish_provider_analysis(job_id, None, error=error, **ledger)
