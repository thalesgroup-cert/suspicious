"""Execute one connector hook/sync with breaker + ledger bookkeeping.

Called from Celery tasks (connectors/tasks.py). Never raises into the
case pipeline: terminal outcomes are ledger rows, retryable failures are
signalled to the Celery task via RetryableDeliveryError.
"""
from __future__ import annotations

import logging
import time

import pybreaker

from common.http_client import get_breaker
from connectors.base import (
    CaseEvent,
    EVENT_CASE_CREATED,
    EVENT_CASE_FINALISED,
)
from connectors.models import ConnectorDelivery, ConnectorState
from connectors.registry import registry

logger = logging.getLogger("connectors.delivery")

MAX_ATTEMPTS = 3

_HOOKS = {
    EVENT_CASE_CREATED: "on_case_created",
    EVENT_CASE_FINALISED: "on_case_finalised",
}


class RetryableDeliveryError(Exception):
    """Raised to the Celery task to trigger a retry (attempt < MAX_ATTEMPTS)."""


def get_state(name: str) -> ConnectorState:
    """Lazy ConnectorState row, seeded from the manifest default."""
    cls = registry.get(name)
    state, _ = ConnectorState.objects.get_or_create(
        name=name, defaults={"enabled": cls.manifest.enabled_by_default}
    )
    return state


def _record(connector, event, case_id, status, error, started, attempt):
    ConnectorDelivery.objects.create(
        connector=connector, event=event, case_id=case_id, status=status,
        error=error[:5000], attempt=attempt,
        duration_ms=int((time.monotonic() - started) * 1000),
    )


def deliver_now(connector_name: str, event_name: str, payload: dict, attempt: int = 1) -> None:
    started = time.monotonic()
    event = CaseEvent.from_dict(payload)
    breaker = get_breaker(connector_name)
    try:
        connector = registry.instantiate(connector_name)
        hook = getattr(connector, _HOOKS[event_name])
        with breaker.calling():
            hook(event)
    except pybreaker.CircuitBreakerError as exc:
        _record(connector_name, event_name, event.case_id,
                ConnectorDelivery.STATUS_SKIPPED, str(exc), started, attempt)
        return
    except Exception as exc:  # noqa: BLE001 — connector code is untrusted
        _record(connector_name, event_name, event.case_id,
                ConnectorDelivery.STATUS_FAILED, str(exc), started, attempt)
        logger.exception("Delivery failed: %s/%s attempt %d",
                         connector_name, event_name, attempt)
        if attempt < MAX_ATTEMPTS:
            raise RetryableDeliveryError(str(exc)) from exc
        return
    _record(connector_name, event_name, event.case_id,
            ConnectorDelivery.STATUS_SUCCESS, "", started, attempt)


def run_sync_now(connector_name: str, attempt: int = 1) -> None:
    """Scheduled-sync variant of deliver_now (event name 'sync', no case)."""
    if not get_state(connector_name).enabled:
        return
    started = time.monotonic()
    breaker = get_breaker(connector_name)
    try:
        connector = registry.instantiate(connector_name)
        with breaker.calling():
            connector.sync()
    except pybreaker.CircuitBreakerError as exc:
        _record(connector_name, "sync", None,
                ConnectorDelivery.STATUS_SKIPPED, str(exc), started, attempt)
        return
    except Exception as exc:  # noqa: BLE001 — connector code is untrusted
        _record(connector_name, "sync", None,
                ConnectorDelivery.STATUS_FAILED, str(exc), started, attempt)
        logger.exception("Sync failed: %s attempt %d", connector_name, attempt)
        if attempt < MAX_ATTEMPTS:
            raise RetryableDeliveryError(str(exc)) from exc
        return
    _record(connector_name, "sync", None,
            ConnectorDelivery.STATUS_SUCCESS, "", started, attempt)
