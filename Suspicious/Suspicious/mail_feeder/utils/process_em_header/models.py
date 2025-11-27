from pydantic import BaseModel, Field, validator
from typing import Dict, Any


class EmailHeaderData(BaseModel):
    """
    Represents validated email header data.
    """
    headers: str = Field(..., min_length=1, description="Raw header string from the email")

    @validator("headers")
    def validate_headers(cls, v):
        if not v.strip():
            raise ValueError("Header value cannot be empty or whitespace.")
        return v


class SimilarityResult(BaseModel):
    """Represents similarity comparison results."""
    fuzzy_hash: str
    distance: float
    is_similar: bool
    threshold: float = Field(default=1.0)