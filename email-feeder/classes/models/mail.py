import typing
import pydantic
import email.message
import classes.models.mail_attachment


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
    tags: str | None = pydantic.Field(default=None)
