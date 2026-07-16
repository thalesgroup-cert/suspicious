import re
from email.utils import parseaddr
from pydantic import BaseModel, EmailStr, Field, validator
from datetime import datetime
from typing import Optional

# Fallback for headers that aren't RFC 5322 "Name <addr>" (parseaddr needs the
# angle brackets to isolate the address) - e.g. GAL-resolved recipients like
# "CLEMENCON Georgia georgia.clemencon@meridian.example [meridian.example]".
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


class EmailDataModel(BaseModel):
    """
    Represents validated raw email data before creating a Mail instance.
    """
    reportedSubject: Optional[str] = Field("", description="Subject of the reported email")
    reportedBy: EmailStr
    # Free-text display field (mail_feeder.models.Mail.to is a CharField, not an
    # address lookup), so raw "To" headers with display names or multiple
    # recipients must not be forced through strict EmailStr validation.
    to: str
    cc: Optional[str] = ""
    bcc: Optional[str] = ""
    date: Optional[str] = None
    id: Optional[str] = ""
    mail_from: Optional[str] = ""

    @validator("reportedSubject", pre=True, always=True)
    def strip_subject(cls, v):
        return str(v or "").strip()

    @validator("reportedBy", pre=True, always=True)
    def extract_reporter_address(cls, v):
        if not v:
            raise ValueError("reportedBy is required and must contain a valid email address.")
        _, addr = parseaddr(v)
        if not addr:
            match = _EMAIL_RE.search(v)
            addr = match.group(0) if match else ""
        if not addr:
            raise ValueError(f"Could not extract a valid email address from: {v!r}")
        return addr

    @validator("to", pre=True, always=True)
    def ensure_to_present(cls, v):
        if not v:
            raise ValueError("to field is required.")
        return v


class MailInstanceResult(BaseModel):
    """
    Represents a successful or failed Mail instance creation result.
    """
    success: bool
    mail_id: Optional[int] = None
    error: Optional[str] = None
