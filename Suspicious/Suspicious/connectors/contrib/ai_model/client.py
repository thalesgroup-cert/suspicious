"""HTTP client for the AI inference server's token-protected /v2 API
(Analyzers/AIMailAnalyzer/inference_server/v2.py)."""
from __future__ import annotations

import re

import requests

from common.http_client import make_session
from connectors.providers import ProviderUnavailable

_MODEL_PATH = "/v2/models/ai_mail"
# The 503 details the server gives when only an operator can fix it: no weights or vectorizer
# to classify with, or no AI_INFERENCE_TOKEN set (it fails closed). A retry changes nothing.
# "Vectorizer unavailable: still loading" is the server starting up, so it is left retryable.
_NEEDS_OPERATOR = re.compile(
    r"(models unavailable|vectorizer unavailable(?!: still loading))|token not configured", re.IGNORECASE
)
# 4xx statuses that say the setup is wrong (token, url, proxy, limits), not this one mail: every
# case would fail the same way, so they fail the row (and count against the breaker) at once.
_SETUP_REFUSED = {
    401: "rejected the token",
    403: "forbade the request, check the token",
    404: "has no {path} endpoint, check the url and the image version",
    407: "needs proxy authentication",
    408: "timed out waiting for the request",
    429: "is rate limiting requests",
}


def _detail(response) -> str:
    try:
        detail = response.json().get("detail", "")
    except (ValueError, AttributeError):
        detail = ""
    return str(detail or getattr(response, "text", "") or "")[:300]


class AiInferenceClient:
    def __init__(self, url: str, token: str, timeout: float):
        self.url = url.rstrip("/")
        self.timeout = timeout
        self._headers = {"Authorization": f"Bearer {token}"}
        self.session = make_session()

    def ready(self) -> tuple[bool, str]:
        """(ok, detail): the server reports ready AND accepts our token. Never raises."""
        try:
            response = self.session.get(f"{self.url}/v2/health/ready", timeout=self.timeout)
            if response.status_code != 200:
                return False, f"not ready (HTTP {response.status_code})"
            response = self.session.get(
                self.url + _MODEL_PATH, headers=self._headers, timeout=self.timeout
            )
        except requests.RequestException as exc:
            return False, f"unreachable: {type(exc).__name__}"
        if response.status_code in (401, 403):
            return False, f"token rejected (HTTP {response.status_code})"
        if response.status_code != 200:
            return False, f"model metadata: HTTP {response.status_code}"
        return True, "ready, token accepted"

    def classify(self, mail_body: str) -> dict:
        return self._post(_MODEL_PATH + "/classify", {"mail_body": mail_body, "versions": ["active"]})

    def embed(self, texts: list[str], profile: str) -> dict:
        """POST /v2/embed: {"vectors", "preprocessing_version", "embedding_version"}.
        Same error handling as classify."""
        return self._post("/v2/embed", {"texts": texts, "profile": profile})

    def _post(self, path: str, payload: dict) -> dict:
        """The server's JSON answer. ProviderUnavailable for what a retry may fix (connection,
        timeout, 5xx), and, with retryable=False, for what only an operator can (models or
        vectorizer not loaded, token missing or rejected, wrong url, rate limit); ValueError
        when the server refused just this request (400, 413, 422 and other 4xx)."""
        try:
            response = self.session.post(
                self.url + path, json=payload,
                headers=self._headers, timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise ProviderUnavailable(f"inference server unreachable: {type(exc).__name__}") from exc
        status = response.status_code
        if status >= 500:
            # Matched on the detail, never stored: only the fixed phrase the pattern found.
            needs_operator = _NEEDS_OPERATOR.search(_detail(response)) if status == 503 else None
            suffix = f": {needs_operator.group(0).lower()}" if needs_operator else ""
            raise ProviderUnavailable(f"inference server HTTP {status}{suffix}", retryable=not needs_operator)
        if status in _SETUP_REFUSED:
            raise ProviderUnavailable(
                f"inference server {_SETUP_REFUSED[status].format(path=path)} (HTTP {status})", retryable=False
            )
        if status != 200:
            # The status only: a 422 detail echoes the request body, so the mail text.
            raise ValueError(f"inference server refused the request (HTTP {status})")
        try:
            return response.json()
        except ValueError as exc:
            raise ProviderUnavailable("inference server sent a non-JSON answer", retryable=False) from exc
