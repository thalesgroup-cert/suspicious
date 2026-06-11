"""Emit case lifecycle events to enabled connectors via Celery fan-out."""
from __future__ import annotations

import logging

from django.db import transaction

from connectors.events import build_case_event
from connectors.registry import registry

logger = logging.getLogger("connectors.dispatch")


def emit(event_name: str, case) -> None:
    """Fan one event out to every enabled subscriber. Enqueued on_commit so
    connectors never observe uncommitted case state. Never raises."""
    try:
        from connectors.delivery import get_state
        from connectors.tasks import deliver_event

        payload = build_case_event(event_name, case).to_dict()
        names = [
            name for name in registry.subscribers(event_name)
            if get_state(name).enabled
        ]
        if not names:
            return

        def _enqueue():
            # Runs at commit time, outside the try below — guard each enqueue
            # so an eager-mode Retry (tests) or broker error can't escape
            # into the committing request/task.
            for name in names:
                try:
                    deliver_event.delay(name, event_name, payload)
                except Exception:  # noqa: BLE001 — fan-out must never raise
                    logger.exception(
                        "deliver_event enqueue failed for %s/%s", name, event_name
                    )

        transaction.on_commit(_enqueue)
    except Exception:  # noqa: BLE001 — emission must never break the pipeline
        logger.exception("emit(%s) failed for case %s",
                         event_name, getattr(case, "id", "?"))
