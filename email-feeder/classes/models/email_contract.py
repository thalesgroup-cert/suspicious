"""Portable per-email metadata contract (mirror of the backend copy at
Suspicious/Suspicious/mail_feeder/email_contract.py). Self-contained: stdlib +
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
