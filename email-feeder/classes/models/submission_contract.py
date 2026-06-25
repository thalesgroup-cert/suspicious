"""Feeder-side mirror of the backend portable submission contract.

Kept identical to Suspicious/Suspicious/mail_feeder/submission_contract.py so the
feeder writes exactly what the backend reader consumes (guarded by `schema`).
"""
import re
from datetime import datetime, timezone

STATUS_OBJECT_NAME = "_status.json"
SUBMISSION_EML_SUFFIX = "submission.eml"
EMAIL_DIR_PATTERN = re.compile(r"^\d{12}-[a-f0-9]+$")

STATUS_TODO = "todo"
STATUS_PROCESSING = "processing"
STATUS_DONE = "done"

CONTRACT_SCHEMA = 1


def build_status(
    submission_id: str,
    reported_by: str,
    emails_to_analyze: list[str],
    attachments: list[str],
    *,
    status: str = STATUS_TODO,
    submitted_at: str | None = None,
) -> dict:
    return {
        "schema": CONTRACT_SCHEMA,
        "status": status,
        "submission_id": submission_id,
        "reported_by": reported_by,
        "emails_to_analyze": emails_to_analyze,
        "attachments": attachments,
        "submitted_at": submitted_at or datetime.now(tz=timezone.utc).isoformat(),
    }
