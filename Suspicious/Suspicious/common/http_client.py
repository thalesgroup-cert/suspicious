"""
common/http_client.py
~~~~~~~~~~~~~~~~~~~~~
Shared HTTP client utilities:
  - TimeoutHTTPAdapter  — injects default connect/read timeout
  - make_session()      — returns a Session with the adapter mounted
  - BREAKERS            — per-integration pybreaker.CircuitBreaker registry (added in next task)
  - get_breaker()       — look up a breaker by integration name (added in next task)
  - RETRY               — tenacity retry decorator (added in next task)
"""
from __future__ import annotations

import requests
from requests.adapters import HTTPAdapter

DEFAULT_CONNECT_TIMEOUT: int = 5   # seconds
DEFAULT_READ_TIMEOUT: int    = 30  # seconds


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
BREAKER_RESET_TIMEOUT: int = 60  # seconds

BREAKERS: dict[str, pybreaker.CircuitBreaker] = {
    "cortex":     pybreaker.CircuitBreaker(fail_max=BREAKER_FAIL_MAX, reset_timeout=BREAKER_RESET_TIMEOUT),
    "thehive":    pybreaker.CircuitBreaker(fail_max=BREAKER_FAIL_MAX, reset_timeout=BREAKER_RESET_TIMEOUT),
    "misp":       pybreaker.CircuitBreaker(fail_max=BREAKER_FAIL_MAX, reset_timeout=BREAKER_RESET_TIMEOUT),
    "virustotal": pybreaker.CircuitBreaker(fail_max=BREAKER_FAIL_MAX, reset_timeout=BREAKER_RESET_TIMEOUT),
}


def get_breaker(name: str) -> pybreaker.CircuitBreaker:
    """Return the CircuitBreaker for the named integration.

    Raises KeyError if *name* is not registered in BREAKERS.
    """
    if name not in BREAKERS:
        raise KeyError(f"No circuit breaker registered for {name!r}")
    return BREAKERS[name]


def _is_retryable_http_error(exc: BaseException) -> bool:
    """Return True for HTTP 5xx errors only — 4xx are client errors, never retried."""
    return (
        isinstance(exc, requests.HTTPError)
        and getattr(exc, "response", None) is not None
        and exc.response.status_code >= 500
    )


#: Retry decorator for outbound integration calls.
#: Retries on ConnectionError, Timeout, and HTTP 5xx.
#: Does NOT retry on HTTP 4xx or CircuitBreakerError.
#: After 3 attempts the original exception is re-raised (reraise=True).
RETRY = tenacity.retry(
    retry=(
        retry_if_exception_type((requests.ConnectionError, requests.Timeout))
        | retry_if_exception(_is_retryable_http_error)
    ),
    wait=wait_exponential(multiplier=1, min=1, max=4),
    stop=stop_after_attempt(3),
    reraise=True,
)
