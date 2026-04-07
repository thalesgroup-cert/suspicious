# analyzers_services/ai/thehive_utils.py
"""
TheHive attachment helper extracted from ai/service.py.
"""
from __future__ import annotations

import logging

import requests

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")

_ATTACHMENT_TIMEOUT = 60  # seconds
_SUCCESS_STATUSES   = {200, 201}


def add_binary_attachment_to_item(
    item_type: str,
    item_id: str,
    filename: str,
    file_bytes: bytes,
    hive_url: str,
    hive_key: str,
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

    response = requests.post(url, headers=headers, files=files, timeout=_ATTACHMENT_TIMEOUT)

    if response.status_code not in _SUCCESS_STATUSES:
        raise RuntimeError(
            "Attachment upload failed for %s/%s (%s): %s" % (
                item_type, item_id, response.status_code, response.text
            )
        )

    logger.info(
        "Attachment %r uploaded to %s %s.", filename, item_type, item_id
    )
    return response.json()