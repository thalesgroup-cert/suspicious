"""Cross-worker mutual exclusion on the shared Django cache."""
from __future__ import annotations

import time
from contextlib import contextmanager

from django.core.cache import cache


@contextmanager
def cache_lock(key: str, *, ttl: int = 60, wait: float = 45.0):
    """Hold ``key`` for the body, waiting up to ``wait`` seconds to get it.

    Used to serialise find-or-create across Celery workers: without it,
    concurrent tasks each miss the lookup and create duplicates. ``ttl`` bounds
    how long a crashed holder can block everyone else.
    """
    deadline = time.monotonic() + wait
    while not cache.add(key, 1, timeout=ttl):
        if time.monotonic() > deadline:
            raise RuntimeError("Timed out waiting for lock %r" % key)
        time.sleep(0.2)
    try:
        yield
    finally:
        cache.delete(key)
