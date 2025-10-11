import typing
import pydantic


class MailAttachment(pydantic.BaseModel):
    filename: str = "N/A"
    file_path: str | None
    content: bytes
    headers: dict[str, list[typing.Any]]
    file_sha256: str | None
    parent: str
