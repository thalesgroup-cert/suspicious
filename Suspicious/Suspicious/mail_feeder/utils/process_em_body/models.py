from pydantic import BaseModel, Field


class EmailBodyData(BaseModel):
    """Validated structure for input email data."""
    reportedText: str = Field(..., min_length=1, description="Raw email body text")
