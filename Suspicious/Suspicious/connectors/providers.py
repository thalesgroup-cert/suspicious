"""Errors shared by connectors that call an analysis service."""
from __future__ import annotations


class ProviderUnavailable(Exception):
    """Raised by a connector (``Connector.run``, the ai_model client) when the service cannot
    answer. A retryable error (connection, timeout, 5xx) is retried by the task; any other fails
    at once."""

    def __init__(self, message: str, retryable: bool = True) -> None:
        super().__init__(message)
        self.retryable = retryable
