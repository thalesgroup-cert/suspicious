"""
TheHive attachment helper extracted from ai/service.py.
"""
from __future__ import annotations

import logging

import pybreaker
import requests

from common.http_client import make_session, get_breaker, RETRY

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")

_ATTACHMENT_TIMEOUT = 60  # seconds — overrides adapter default (attachments can be large)

_session         = make_session()
_thehive_breaker = get_breaker("thehive")


@RETRY
def _upload(url: str, headers: dict, files: dict, timeout: int, verify) -> requests.Response:
    """POST a file upload with retry and circuit breaker. Raises HTTPError on non-2xx."""
    with _thehive_breaker.calling():
        response = _session.post(url, headers=headers, files=files, timeout=timeout, verify=verify)
        response.raise_for_status()
        return response


def add_binary_attachment_to_item(
    item_type: str,
    item_id: str,
    filename: str,
    file_bytes: bytes,
    hive_url: str,
    hive_key: str,
    verify: str | bool = True,
) -> dict:
    """
    Upload a binary file as an attachment to a TheHive alert or case.

    Raises ValueError for invalid item_type, RuntimeError for HTTP errors.
    """
    if item_type not in ("alert", "case"):
        raise ValueError("item_type must be 'alert' or 'case', got %r." % item_type)

    url     = "%s/api/v1/%s/%s/attachment" % (hive_url, item_type, item_id)
    headers = {"Authorization": "Bearer %s" % hive_key}
    files   = {"file": (filename, file_bytes, "application/zip")}

    try:
        response = _upload(url, headers, files, _ATTACHMENT_TIMEOUT, verify)
    except pybreaker.CircuitBreakerError as e:
        raise RuntimeError(
            "TheHive circuit breaker open — attachment upload skipped for %s/%s" % (item_type, item_id)
        ) from e
    except requests.HTTPError as e:
        resp = e.response
        raise RuntimeError(
            "Attachment upload failed for %s/%s (%s): %s" % (
                item_type, item_id,
                resp.status_code if resp is not None else "?",
                resp.text if resp is not None else str(e),
            )
        ) from e

    logger.info(
        "Attachment %r uploaded to %s %s.", filename, item_type, item_id
    )
    return response.json()