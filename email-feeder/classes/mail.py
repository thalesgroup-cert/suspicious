import dataclasses


@dataclasses.dataclass(eq=False, repr=False)
class Mail:
    sender: str
    recipients: str
    bcc: str
    date: str
    body: str
    headers: str
    subject: str
    cc: str
    attachments: str
    eml: str
    html: str
    new_id: str
    case_path: str
    tags: str | None = dataclasses.field(default=None)
