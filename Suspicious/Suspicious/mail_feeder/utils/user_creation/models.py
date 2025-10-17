from pydantic import BaseModel, EmailStr, Field, validator
from typing import List, Optional


class ConfigModel(BaseModel):
    company_domains: List[str] = Field(..., description="List of authorized company domains")
    suspicious_email: EmailStr = Field(..., description="Fallback email for suspicious users")


class UsernameModel(BaseModel):
    username: EmailStr

    @validator("username")
    def validate_username(cls, v):
        if not v:
            raise ValueError("Username cannot be empty.")
        return v
