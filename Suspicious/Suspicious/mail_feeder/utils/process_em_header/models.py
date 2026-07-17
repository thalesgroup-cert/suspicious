from pydantic import BaseModel, Field, validator


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