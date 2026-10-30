"""HTTP client for the AI inference server's token-protected /v2 API
(Analyzers/AIMailAnalyzer/inference_server/v2.py)."""
from __future__ import annotations

import re

import requests

from common.http_client import make_session
from connectors.providers import ProviderUnavailable

_MODEL_PATH = "/v2/models/ai_mail"
# The 503 details the server gives when it has no weights / vectorizer to classify with.
_NOT_LOADED = re.compile(r"(models|vectorizer) unavailable", re.IGNORECASE)


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
        """The server's JSON answer. ProviderUnavailable for what a retry may fix (connection,
        timeout, 5xx) or what only an operator can (models/vectorizer not loaded); ValueError
        when the server refused this request (4xx)."""
        try:
            response = self.session.post(
                self.url + _MODEL_PATH + "/classify",
                json={"mail_body": mail_body, "versions": ["active"]},
                headers=self._headers, timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise ProviderUnavailable(f"inference server unreachable: {type(exc).__name__}") from exc
        status = response.status_code
        if status >= 500:
            detail = _detail(response)
            retryable = not (status == 503 and _NOT_LOADED.search(detail))
            raise ProviderUnavailable(f"inference server HTTP {status}: {detail}", retryable=retryable)
        if status != 200:
            raise ValueError(f"inference server refused the request (HTTP {status}): {_detail(response)}")
        try:
            return response.json()
        except ValueError as exc:
            raise ProviderUnavailable("inference server sent a non-JSON answer", retryable=False) from exc
