"""Portable per-email metadata contract (mirror of the feeder copy at
email-feeder/classes/models/email_contract.py). Self-contained: stdlib +
pydantic only, so both copies stay byte-identical.

The feeder writes one `email.json` per analyzed email so the backend can build
its EmailDataModel without re-parsing the .eml. Extractors live in this module
too, so the feeder writer and the backend fallback share one source of truth.
"""
import hashlib
import re
import typing
from email.header import decode_header, make_header
from email.message import Message
from email.utils import getaddresses

import pydantic

CONTRACT_SCHEMA = 1
EMAIL_METADATA_OBJECT_NAME = "email.json"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class EmailAttachmentMeta(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="forbid")
    filename: str
    sha256: str
    headers: dict[str, str] = pydantic.Field(default_factory=dict)

    @pydantic.field_validator("sha256")
    @classmethod
    def _hex(cls, v: str) -> str:
        if not _SHA256_RE.match(v):
            raise ValueError(f"sha256 must be 64 lowercase hex chars: {v!r}")
        return v


class EmailMetadata(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="forbid", populate_by_name=True)
    schema_version: typing.Literal[CONTRACT_SCHEMA] = pydantic.Field(
        default=CONTRACT_SCHEMA, alias="schema"
    )
    id: str = pydantic.Field(min_length=1)
    from_: str | None = pydantic.Field(default=None, alias="from")
    to: str | None = None
    cc: str | None = None
    bcc: str | None = None
    reportedSubject: str = ""
    reportedText: list[str] = pydantic.Field(default_factory=list)
    date: str = ""
    headers: dict[str, str] = pydantic.Field(default_factory=dict)
    attachments: list[EmailAttachmentMeta] = pydantic.Field(default_factory=list)


def decode_header_value(raw: str | None) -> str:
    if raw is None:
        return ""
    try:
        return str(make_header(decode_header(raw)))
    except Exception:
        return str(raw)


def extract_address(header_value: str | None) -> str | None:
    decoded = decode_header_value(header_value)
    for _, addr in getaddresses([decoded]):
        if addr:
            return addr.lower()
    return None


def extract_text_parts(msg: Message) -> list[str]:
    parts: list[str] = []
    for part in msg.walk():
        if part.get_content_type() in ("text/plain", "text/html"):
            try:
                payload = part.get_payload(decode=True)
            except Exception:
                continue
            if payload:
                parts.append(payload.decode(
                    part.get_content_charset("utf-8"), errors="replace"))
    return parts


def extract_header_dict(msg: Message) -> dict[str, str]:
    return {k: decode_header_value(v) for k, v in msg.items()}


def extract_attachment_metas(msg: Message) -> list[EmailAttachmentMeta]:
    metas: list[EmailAttachmentMeta] = []
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        if "attachment" not in (part.get("Content-Disposition", "") or "").lower():
            continue
        raw_name = part.get_filename()
        if not raw_name:
            continue
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""
        metas.append(EmailAttachmentMeta(
            filename=decode_header_value(raw_name),
            sha256=hashlib.sha256(payload).hexdigest(),
            headers={k: decode_header_value(v) for k, v in part.items()},
        ))
    return metas


def resolve_reporter_and_to(to: str | None, reported_by: str) -> tuple[str, str]:
    """Shared post-extraction massaging used by both parse_email (fallback)
    and build_email_data_model (fast path). Returns (to, reporter)."""
    if not to or to in ("", "Undisclosed recipients:;"):
        to = "no.recipient@noemail.com"
    reporter = reported_by if reported_by else to
    return to, (reporter or to)


def build_email_metadata(msg: Message, email_id: str) -> EmailMetadata:
    return EmailMetadata(
        id=email_id,
        from_=extract_address(msg.get("From")),
        to=extract_address(msg.get("To")),
        cc=extract_address(msg.get("Cc")),
        bcc=extract_address(msg.get("Bcc")),
        reportedSubject=decode_header_value(msg.get("Subject", "")),
        reportedText=extract_text_parts(msg),
        date=msg.get("Date", "") or "",
        headers=extract_header_dict(msg),
        attachments=extract_attachment_metas(msg),
    )
