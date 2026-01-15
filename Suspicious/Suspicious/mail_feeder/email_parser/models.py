from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List, Dict, Any


class AttachmentModel(BaseModel):
    """
    Model representing an email attachment.
    """
    filename: str
    content: bytes
    headers: Dict[str, str]
    parent: str


class EmailDataModel(BaseModel):
    """
    Model representing parsed email data.
    """
    reportedBy: str
    from_addr: str = Field(..., alias="from")
    to: str
    cc: Optional[str] = ""
    bcc: Optional[str] = ""
    reportedSubject: str
    reportedText: List[str]
    date: str
    headers: Dict[str, str]
    id: str
    attachments: List[AttachmentModel]
