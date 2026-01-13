from pydantic import BaseModel, Field, HttpUrl
from typing import Optional


class MinioConfig(BaseModel):
    endpoint: str
    access_key: str
    secret_key: str
    secure: bool = False


class CortexConfig(BaseModel):
    url: HttpUrl
    api_key: str


class CronConfig(BaseModel):
    minio: MinioConfig
    cortex: Optional[CortexConfig] = None
    temp_dir: str = Field(default="/tmp/emailAnalysis/")
    suspicious_path: Optional[str] = Field(default="/app/Suspicious/chromadb")
