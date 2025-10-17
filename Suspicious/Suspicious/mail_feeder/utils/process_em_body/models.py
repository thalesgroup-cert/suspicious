from pydantic import BaseModel, Field
from typing import Optional


class EmailBodyData(BaseModel):
    """Validated structure for input email data."""
    reportedText: str = Field(..., min_length=1, description="Raw email body text")


class SimilarityResult(BaseModel):
    """Represents similarity comparison results."""
    fuzzy_hash: str
    distance: float
    is_similar: bool
    threshold: float = Field(default=1.0)
