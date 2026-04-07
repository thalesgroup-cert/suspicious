# misp/models.py
from pydantic import AnyUrl, BaseModel, Field
from typing import Any, Dict, Optional


class MISPConfig(BaseModel):
    url:         AnyUrl
    key:         str
    ssl_verify:  bool = False   # read from config, not hardcoded in client


class MISPSettings(BaseModel):
    suspicious: MISPConfig
    security:   MISPConfig
    tags:       Optional[Dict[str, Any]] = Field(default_factory=dict)