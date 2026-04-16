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
