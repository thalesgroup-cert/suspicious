from pydantic import BaseModel, ConfigDict
from typing import Any, Dict, Optional


class AnalyzerResult(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    analyzer_name: str
    data: str
    score: int
    confidence: int
    category: str | list[str]
    level: str
    details: dict[str, Any]



class AllowListResult(BaseModel):
    FileAllowList: Optional[str] = None
    DomainAllowList: Optional[str] = None
    FiletypeAllowList: Optional[str] = None
