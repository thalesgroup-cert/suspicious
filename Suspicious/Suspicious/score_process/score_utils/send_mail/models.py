from pydantic import BaseModel
from typing import Optional

from dataclasses import dataclass

class UserInfo(BaseModel):
    email: str
    display_name: str


class RetryConfig(BaseModel):
    max_retries: int = 3
    base_delay: int = 1


class SuspiciousConfig(BaseModel):
    email: str


class AcknowledgeMailServiceConfigSocial(BaseModel):
    name: str
    url: str
    logo_svg: Optional[str] = None
    logo_png: Optional[str] = None


class FinalMailServiceConfigSocial(BaseModel):
    name: str
    url: str
    logo_svg: Optional[str] = None
    logo_png: Optional[str] = None


class ModificationMailServiceConfigSocial(BaseModel):
    name: str
    url: str
    logo_svg: Optional[str] = None
    logo_png: Optional[str] = None

@dataclass(frozen=True)
class EmailSubjectsConfig:
    acknowledgement: str
    review: str
    final: str
