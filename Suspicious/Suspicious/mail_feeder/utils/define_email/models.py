from pydantic import BaseModel, EmailStr, Field, validator
from datetime import datetime
from typing import Optional


class EmailDataModel(BaseModel):
    """
    Represents validated raw email data before creating a Mail instance.
    """
    reportedSubject: Optional[str] = Field("", description="Subject of the reported email")
    reportedBy: EmailStr
    to: EmailStr
    cc: Optional[str] = ""
    bcc: Optional[str] = ""
    date: Optional[str] = None
    id: Optional[str] = ""
    mail_from: Optional[str] = ""

    @validator("reportedSubject", pre=True, always=True)
    def strip_subject(cls, v):
        return str(v or "").strip()

    @validator("reportedBy", "to", pre=True, always=True)
    def ensure_email_format(cls, v):
        if not v:
            raise ValueError("ReportedBy and To fields are required and must be valid emails.")
        return v


class MailInstanceResult(BaseModel):
    """
    Represents a successful or failed Mail instance creation result.
    """
    success: bool
    mail_id: Optional[int] = None
    error: Optional[str] = None
