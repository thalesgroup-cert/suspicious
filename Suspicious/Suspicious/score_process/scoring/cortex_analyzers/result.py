"""Analyzer result model + the PENDING sentinel (report not finished)."""
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, field_validator


class AnalyzerResult(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    analyzer_name: str
    data:          Any
    score:         int
    confidence:    int
    category:      str | list[str]
    level:         str
    details:       dict[str, Any]

    @field_validator("data", mode="before")
    @classmethod
    def coerce_data_to_str(cls, v: Any) -> str:
        return str(v)


class AllowListResult(BaseModel):
    FileAllowList:     Optional[str] = None
    DomainAllowList:   Optional[str] = None
    FiletypeAllowList: Optional[str] = None


# Sentinel: analyzer job not finished — the report must NOT be scored.
PENDING = object()
