from pydantic import BaseModel, Field, HttpUrl, EmailStr, validator
from typing import Optional, Literal


class ArtifactModel(BaseModel):
    dataType: Literal['mail', 'domain', 'url', 'ip', 'hash', 'file']
    data: str = Field(..., min_length=1)

    @validator('data')
    def strip_data(cls, v: str) -> str:
        return v.strip()


class URLDecodeResult(BaseModel):
    prime_url: Optional[HttpUrl]
    decoded_url: Optional[HttpUrl]


class ConfigModel(BaseModel):
    company_domains: Optional[list[str]] = None


class EmailValidationResult(BaseModel):
    normalized: Optional[EmailStr]
    is_valid: bool = False
