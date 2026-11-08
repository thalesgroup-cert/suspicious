"""
common/http_client.py
~~~~~~~~~~~~~~~~~~~~~
Shared HTTP client utilities:
  - TimeoutHTTPAdapter: injects default connect/read timeout
  - make_session(): returns a Session with the adapter mounted
  - BREAKERS: per-integration pybreaker.CircuitBreaker registry
  - get_breaker(): look up / create a breaker by integration name
  - RETRY: tenacity retry decorator
  - breaker_state() / request_reset(): a breaker's state as the processes publish it to the
    shared Django cache, and a reset every process applies before its next call
"""
from __future__ import annotations

import logging
import time
from datetime import UTC, datetime

import requests
from django.core.cache import cache
from requests.adapters import HTTPAdapter

DEFAULT_CONNECT_TIMEOUT: int = 5
DEFAULT_READ_TIMEOUT: int    = 30


class TimeoutHTTPAdapter(HTTPAdapter):
    """HTTPAdapter that injects a default timeout when the caller doesn't supply one."""

    def __init__(
        self,
        connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
        read_timeout: int = DEFAULT_READ_TIMEOUT,
        **kwargs,
    ):
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        super().__init__(**kwargs)

    def send(self, request, **kwargs):
        if kwargs.get("timeout") is None:
            kwargs["timeout"] = (self.connect_timeout, self.read_timeout)
        return super().send(request, **kwargs)


def make_session(
    connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
    read_timeout: int = DEFAULT_READ_TIMEOUT,
) -> requests.Session:
    """Return a requests.Session with TimeoutHTTPAdapter mounted on http:// and https://."""
    session = requests.Session()
    adapter = TimeoutHTTPAdapter(connect_timeout=connect_timeout, read_timeout=read_timeout)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


import pybreaker
import tenacity
from tenacity import (
    retry_if_exception,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

BREAKER_FAIL_MAX: int      = 5
BREAKER_RESET_TIMEOUT: int = 60

logger = logging.getLogger(__name__)


class _LogStateChange(pybreaker.CircuitBreakerListener):
    """Log each state change of a breaker: an opening at WARNING, the rest at INFO."""

    def state_change(self, cb, old_state, new_state):
        level = logging.WARNING if new_state.name == pybreaker.STATE_OPEN else logging.INFO
        logger.log(level, "circuit breaker %s: %s -> %s",
                   cb.name, getattr(old_state, "name", None), new_state.name)


# pybreaker state lives in each process (gunicorn worker, celery worker). Each process publishes
# its state changes to the shared cache (last writer wins) and reads a reset epoch before a call.
# Neither key has a TTL: the state carries its own "since", and the epoch must outlive any one
# process. A flushed cache means "unknown" and an epoch re-seeded from the clock (always new).
STATE_KEY = "breaker:{}"
EPOCH_KEY = "breaker-epoch:{}"
EPOCH_CHECK_SECONDS = 5  # ponytail: at most one cache read per breaker per 5 s, so a reset lands within that
_UNKNOWN = {"state": "unknown", "since": None}
_STATES = (pybreaker.STATE_CLOSED, pybreaker.STATE_OPEN, pybreaker.STATE_HALF_OPEN)
_publish_failing = False  # log a failing publish once per outage, not per state change


class _PublishState(pybreaker.CircuitBreakerListener):
    """Write {state, since} to the shared cache. Never raises: a cache outage must not break a call."""

    def state_change(self, cb, old_state, new_state):
        global _publish_failing
        try:
            cache.set(STATE_KEY.format(cb.name),
                      {"state": new_state.name, "since": datetime.now(UTC).isoformat()}, timeout=None)
            _publish_failing = False
        except Exception:  # noqa: BLE001 — any cache error
            if not _publish_failing:
                _publish_failing = True
                logger.warning("circuit breaker %s: could not publish its state to the cache", cb.name)


class _EpochBreaker(pybreaker.CircuitBreaker):
    """A breaker that closes itself, once, when an admin moved the reset epoch. ``calling()``
    goes through ``call()`` so both paths check. The check fails open: no cache, no change."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._epoch = None  # the last epoch this process applied (None: never seen one)
        self._epoch_checked = float("-inf")

    def _sync_epoch(self):
        now = time.monotonic()
        with self._lock:  # the breaker's own RLock: one lock order, and close() re-enters it
            if now - self._epoch_checked < EPOCH_CHECK_SECONDS:
                return
            self._epoch_checked = now
            try:
                epoch = cache.get(EPOCH_KEY.format(self.name))
            except Exception:  # noqa: BLE001 — cache down: the breaker behaves as before
                return
            if epoch is None or epoch == self._epoch:
                return
            # A process seeing its first epoch with a closed breaker has nothing to undo.
            if self._epoch is not None or self.current_state != pybreaker.STATE_CLOSED:
                self.close()
            self._epoch = epoch

    def call(self, func, *args, **kwargs):
        self._sync_epoch()
        return super().call(func, *args, **kwargs)


def _new_breaker(name: str) -> pybreaker.CircuitBreaker:
    return _EpochBreaker(
        fail_max=BREAKER_FAIL_MAX, reset_timeout=BREAKER_RESET_TIMEOUT,
        name=name, listeners=[_LogStateChange(), _PublishState()],
    )


def breaker_state(name: str) -> dict:
    """{state, since} as last published by any process; unknown when absent or the cache fails."""
    try:
        value = cache.get(STATE_KEY.format(name))
    except Exception:  # noqa: BLE001
        return dict(_UNKNOWN)
    if not isinstance(value, dict) or value.get("state") not in _STATES:
        return dict(_UNKNOWN)
    return {"state": value["state"], "since": value.get("since")}


def request_reset(name: str) -> int:
    """Move the reset epoch for *name* and return it. Cache errors propagate (the caller answers 503).
    A missing key is seeded from the clock, so a flushed cache never repeats an epoch a process holds."""
    key = EPOCH_KEY.format(name)
    cache.add(key, time.time_ns(), timeout=None)
    return cache.incr(key)


BREAKERS: dict[str, pybreaker.CircuitBreaker] = {
    name: _new_breaker(name) for name in ("cortex", "thehive", "misp", "virustotal")
}


def ensure_breaker(name: str) -> pybreaker.CircuitBreaker:
    """Return the breaker for *name*, creating it with default thresholds
    if absent. Used by the connector registry so dynamically discovered
    connectors get isolation without editing this module."""
    if name not in BREAKERS:
        BREAKERS[name] = _new_breaker(name)
    return BREAKERS[name]


def get_breaker(name: str) -> pybreaker.CircuitBreaker:
    """Return the CircuitBreaker for the named integration (create-on-demand)."""
    return ensure_breaker(name)


def _is_retryable_http_error(exc: BaseException) -> bool:
    """Return True for HTTP 5xx errors only; 4xx are client errors, never retried."""
    return (
        isinstance(exc, requests.HTTPError)
        and getattr(exc, "response", None) is not None
        and exc.response.status_code >= 500
    )


RETRY = tenacity.retry(
    retry=(
        retry_if_exception_type((requests.ConnectionError, requests.Timeout))
        | retry_if_exception(_is_retryable_http_error)
    ),
    wait=wait_exponential(multiplier=1, min=1, max=4),
    stop=stop_after_attempt(3),
    reraise=True,
)
