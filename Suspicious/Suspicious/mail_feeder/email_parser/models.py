from pydantic import BaseModel, Field, field_validator
from typing import Optional, List, Dict


class AttachmentModel(BaseModel):
    filename: str
    content: bytes
    headers: Dict[str, str]
    parent: str


class EmailDataModel(BaseModel):
    reportedBy: str
    from_addr: str = Field(..., alias="from")

    to: Optional[str] = None
    cc: Optional[str] = None
    bcc: Optional[str] = None

    reportedSubject: str
    reportedText: List[str]
    date: str
    headers: Dict[str, str]
    id: str
    attachments: List[AttachmentModel]

    # Nettoyage automatique des valeurs vides
    @field_validator("to", "cc", "bcc", mode="before")
    @classmethod
    def empty_to_none(cls, v):
        return v or None