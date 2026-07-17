import typing
import pydantic
import email.message
import classes.models.mail_attachment
import classes.models.mail_tags


class SuspiciousMailRequest(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(arbitrary_types_allowed=True)

    id: bytes
    to: list[str]
    cc: list[str]
    bcc: list[str]
    date: str | None
    subject: str | None
    from_address: str | None
    from_header_raw: typing.Any | None
    body_text: str
    body_html: str
    headers_parsed: email.message.Message | dict[str, str]
    raw_eml_bytes: bytes
    attachments: list[classes.models.mail_attachment.MailAttachment]


class SuspiciousMailResponse(pydantic.BaseModel):
    original_mail: SuspiciousMailRequest
    id: str
    case_path: str
    outcome: classes.models.mail_tags.SubmissionOutcome
    submission_dir: str
    """Top-level dir under working_path (the forwarded wrapper). For a VALID
    submission this whole dir is uploaded to S3; for a bad one it is cleaned up
    without upload."""

    reported_by: str = ""
    """Address of the person who submitted the report — the forwarding employee
    (the wrapper's From), NOT the inner attacker. Drives the contract's
    `reported_by`, which the backend uses to notify the reporter. Defaults to ""
    so non-forwarded paths stay valid."""

    reporter_note: str = ""
    """Reporter's note (the wrapper body). Submission-level, shared by every
    analyzed email under the wrapper. Drives _status.json reporter_note."""
