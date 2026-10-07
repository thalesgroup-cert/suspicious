"""Emit case lifecycle events to enabled connectors via Celery fan-out."""
from __future__ import annotations

import logging

from django.db import transaction

from connectors.base import EVENT_CASE_CREATED
from connectors.events import build_case_event
from connectors.registry import registry

logger = logging.getLogger("connectors.dispatch")

# case_created fires as soon as the Case row exists, before ingest has written
# the rows connectors read (e.g. MailInfo). A few seconds' head start avoids a
# spurious failed first attempt in the ledger.
_START_DELAY_SECONDS = {EVENT_CASE_CREATED: 5}


def emit(event_name: str, case, campaign_id: int | None = None) -> None:
    """Fan one event out to every enabled subscriber. Enqueued on_commit so
    connectors never observe uncommitted case state. Never raises."""
    try:
        from connectors.delivery import get_state
        from connectors.tasks import deliver_event

        payload = build_case_event(event_name, case, campaign_id).to_dict()
        names = [
            name for name in registry.subscribers(event_name)
            if get_state(name).enabled
        ]
        if not names:
            return

        def _enqueue():
            for name in names:
                try:
                    deliver_event.apply_async(
                        (name, event_name, payload),
                        countdown=_START_DELAY_SECONDS.get(event_name, 0),
                    )
                except Exception:  # noqa: BLE001 — fan-out must never raise
                    logger.exception(
                        "deliver_event enqueue failed for %s/%s", name, event_name
                    )

        transaction.on_commit(_enqueue)
    except Exception:  # noqa: BLE001 — emission must never break the pipeline
        logger.exception("emit(%s) failed for case %s",
                         event_name, getattr(case, "id", "?"))
