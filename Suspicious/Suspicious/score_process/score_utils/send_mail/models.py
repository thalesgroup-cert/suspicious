from pydantic import BaseModel
from typing import Optional


class UserInfo(BaseModel):
    email: str
    display_name: str


class RetryConfig(BaseModel):
    max_retries: int = 3
    base_delay: int = 1


class SuspiciousConfig(BaseModel):
    email: str
