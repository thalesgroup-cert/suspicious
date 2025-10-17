from pydantic import BaseModel, Field, validator
from typing import Any, Dict, Optional


class EmailDataModel(BaseModel):
    """
    Pydantic model for validating input email data.
    """
    id: str = Field(..., description="Unique identifier of the email")
    reportedText: Optional[str] = Field(None, description="Body text of the email")
    headers: Optional[Dict[str, Any]] = Field(None, description="Email headers")
    sender: Optional[str] = Field(None, description="Sender email address")
    subject: Optional[str] = Field(None, description="Subject line of the email")

    @validator("id")
    def id_must_not_be_empty(cls, v):
        if not v.strip():
            raise ValueError("Email ID cannot be empty.")
        return v
