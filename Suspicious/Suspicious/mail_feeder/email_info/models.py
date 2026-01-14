from pydantic import BaseModel, EmailStr, Field, PositiveInt
from typing import Optional


class MailInstanceModel(BaseModel):
    """
    Pydantic model representing the minimal validated fields of a mail instance.
    """
    reportedBy: EmailStr = Field(..., description="Email address of the reporter")
    times_sent: PositiveInt = Field(1, description="Number of times the mail was sent")


class MailInfoData(BaseModel):
    """
    Model for creating or updating MailInfo entries.
    """
    user_email: EmailStr
    mail_id: str
    is_received: bool = True
    is_phishing: bool = False
