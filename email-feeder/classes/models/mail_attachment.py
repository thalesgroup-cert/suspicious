import typing
import pydantic


class MailAttachment(pydantic.BaseModel):
    filename: str = "N/A"
    file_path: str | None
    content: bytes
    headers: dict[str, list[typing.Any]]
    file_sha256: str | None
    parent: str
    is_email: bool = False
    """True when this attachment is itself a mail (message/rfc822 or *.eml) —
    i.e. the suspicious item the user forwarded for analysis."""
