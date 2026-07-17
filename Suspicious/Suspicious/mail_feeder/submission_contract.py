"""Shared definition of the portable feeder S3 contract.

One feeder bucket; each submission is a prefix `<submission-id>/`. Status and
the manifest live together in `<submission-id>/_status.json`. This module is
the single source of truth for the contract used by both the backend reader
(tasp/cron/fetch_emails.py) and the Go feeder (kept in sync by the `schema`
field).
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

STATUS_OBJECT_NAME = "_status.json"
SUBMISSION_EML_SUFFIX = "submission.eml"
EMAIL_DIR_PATTERN = re.compile(r"^\d{12}-[a-f0-9]+$")

STATUS_TODO = "todo"
STATUS_PROCESSING = "processing"
STATUS_DONE = "done"

CONTRACT_SCHEMA = 1

REPORTER_NOTE_MAX_BYTES = 8192


def build_status(
    status: str,
    *,
    submission_id: str,
    reported_by: str,
    emails_to_analyze: list[str],
    attachments: list[str],
    submitted_at: str | None = None,
    reporter_note: str = "",
) -> dict:
    return {
        "schema": CONTRACT_SCHEMA,
        "status": status,
        "submission_id": submission_id,
        "reported_by": reported_by,
        "emails_to_analyze": emails_to_analyze,
        "attachments": attachments,
        "submitted_at": submitted_at
        or datetime.now(tz=timezone.utc).isoformat(),
        "reporter_note": reporter_note[:REPORTER_NOTE_MAX_BYTES],
    }


def parse_status(raw: bytes | str) -> dict:
    try:
        data = json.loads(raw)
    except (ValueError, TypeError) as e:
        raise ValueError(f"invalid _status.json: {e}") from e
    if not isinstance(data, dict) or "status" not in data:
        raise ValueError("_status.json missing 'status'")
    return data
