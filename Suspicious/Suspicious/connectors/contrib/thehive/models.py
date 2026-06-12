from typing import List, Optional, Literal
from pydantic import BaseModel, Field, HttpUrl, conint, EmailStr


class TheHiveConfig(BaseModel):
    url: HttpUrl
    api_key: str
    user: Optional[str] = None
    certificate_path: Optional[str] = None


class AlertCreate(BaseModel):
    title: str
    description: str
    severity: conint(ge=1, le=4) = 1
    tlp: conint(ge=0, le=4) = 1
    pap: conint(ge=0, le=4) = 1
    app_name: str
    source_ref: str
    tags: List[str] = Field(default_factory=lambda: ["suspicious"])


class Observable(BaseModel):
    dataType: Literal["url", "mail", "mail-subject", "other"]
    data: str
    tlp: int = 1
    pap: int = 1
    tags: List[str]
    message: str


class Comment(BaseModel):
    message: str


class ChallengerModel(BaseModel):
    firstname: Optional[str] = None
    lastname: Optional[str] = None
    email: Optional[EmailStr] = None
    groups: List[str] = []


class ArtifactModel(BaseModel):
    value: str
    datatype: str = Field(pattern="^(ip|url|hash|mail|domain)$")


class CaseModel(BaseModel):
    id: int
    score: Optional[float] = None
    confidence: Optional[float] = None
    results: Optional[str] = None
    category_ai: Optional[str] = None
    results_ai: Optional[str] = None
    score_ai: Optional[float] = None
    confidence_ai: Optional[float] = None


class MailModel(BaseModel):
    subject: Optional[str] = None
    mail_from: Optional[str] = None
    mail_id: Optional[str] = None


class MinioConfig(BaseModel):
    endpoint: str
    access_key: str
    secret_key: str