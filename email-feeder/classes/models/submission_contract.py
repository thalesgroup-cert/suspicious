"""Feeder-side mirror of the backend portable submission contract.

Kept identical to Suspicious/Suspicious/mail_feeder/submission_contract.py so the
feeder writes exactly what the backend reader consumes (guarded by `schema`).
"""
import re
import typing
from datetime import datetime, timezone

import pydantic

STATUS_OBJECT_NAME = "_status.json"
SUBMISSION_EML_SUFFIX = "submission.eml"
EMAIL_DIR_PATTERN = re.compile(r"^\d{12}-[a-f0-9]+$")

STATUS_TODO = "todo"
STATUS_PROCESSING = "processing"
STATUS_DONE = "done"

CONTRACT_SCHEMA = 1

REPORTER_NOTE_MAX_BYTES = 8192


class SubmissionStatus(pydantic.BaseModel):
    """Validated shape of `_status.json`.

    Validating at write time turns a malformed manifest into a loud
    ValidationError in the feeder (where the offending submission is in hand)
    instead of a silent skip or a crash on the backend reader. `extra="forbid"`
    catches key drift between this mirror and the backend contract; the schema
    version is pinned so an incompatible bump fails fast rather than being
    misread.
    """

    model_config = pydantic.ConfigDict(extra="forbid", populate_by_name=True)

    schema_version: typing.Literal[CONTRACT_SCHEMA] = pydantic.Field(
        default=CONTRACT_SCHEMA, alias="schema"
    )
    status: typing.Literal[STATUS_TODO, STATUS_PROCESSING, STATUS_DONE]
    submission_id: str = pydantic.Field(min_length=1)
    reported_by: str
    emails_to_analyze: list[str]
    attachments: list[str]
    submitted_at: str
    reporter_note: str = ""

    @pydantic.field_validator("submitted_at")
    @classmethod
    def _iso8601(cls, value: str) -> str:
        try:
            datetime.fromisoformat(value)
        except (TypeError, ValueError) as e:
            raise ValueError(f"submitted_at must be ISO-8601: {value!r}") from e
        return value


def build_status(
    submission_id: str,
    reported_by: str,
    emails_to_analyze: list[str],
    attachments: list[str],
    *,
    status: str = STATUS_TODO,
    submitted_at: str | None = None,
    reporter_note: str = "",
) -> dict:
    """Build the validated `_status.json` manifest dict.

    Raises pydantic.ValidationError on malformed input so a bad submission is
    rejected at write time rather than surfacing downstream.
    """
    model = SubmissionStatus(
        status=status,
        submission_id=submission_id,
        reported_by=reported_by,
        emails_to_analyze=emails_to_analyze,
        attachments=attachments,
        submitted_at=submitted_at or datetime.now(tz=timezone.utc).isoformat(),
        reporter_note=reporter_note[:REPORTER_NOTE_MAX_BYTES],
    )
    return model.model_dump(by_alias=True)
