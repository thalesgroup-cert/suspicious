from pydantic import BaseModel, AnyUrl, Field
from typing import Optional, Dict, Any, List


class MISPConfig(BaseModel):
    url: AnyUrl
    key: str


class MISPSettings(BaseModel):
    suspicious: MISPConfig
    security: MISPConfig
    tags: Optional[Dict[str, Any]] = {}

