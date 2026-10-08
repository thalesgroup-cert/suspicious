"""Pay a gunicorn worker's one-off start-up cost before its first request.

A worker that has only loaded Django imports every view and serializer reachable
from the URLconf when it serves its first request, about 1.5 s on the first
call. Workers restart every ~1000 requests, so a different user paid for it each
time. ``gunicorn.conf.py`` calls ``warm_up`` from ``post_worker_init``.
"""
from __future__ import annotations

import time


def warm_up() -> float | None:
    """Import the URLconf and everything it pulls in. Returns the seconds spent,
    or None if it failed; it never raises (a failure only means the first
    request pays the cost, as it did before)."""
    started = time.monotonic()
    try:
        from django.urls import get_resolver

        get_resolver().url_patterns  # noqa: B018 - evaluating it imports the views
    except Exception:  # noqa: BLE001 - warming is best effort
        return None
    return time.monotonic() - started
