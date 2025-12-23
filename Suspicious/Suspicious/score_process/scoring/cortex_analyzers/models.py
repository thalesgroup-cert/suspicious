from pydantic import BaseModel
from typing import Any, Dict, Optional


class AnalyzerResult(BaseModel):
    analyzer_name: str
    data: str
    score: int
    confidence: int
    category: str | list[str]
    level: str
    details: Dict[str, Any]


class AllowListResult(BaseModel):
    FileAllowList: Optional[str] = None
    DomainAllowList: Optional[str] = None
    FiletypeAllowList: Optional[str] = None
