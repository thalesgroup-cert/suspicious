# score_process/scoring/cortex_analyzers/models.py
"""
Pydantic models for analyzer results.
"""
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, field_validator


class AnalyzerResult(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    analyzer_name: str
    data:          Any      # coerced to str — see validator below
    score:         int
    confidence:    int
    category:      str | list[str]
    level:         str
    details:       dict[str, Any]

    @field_validator("data", mode="before")
    @classmethod
    def coerce_data_to_str(cls, v: Any) -> str:
        """Ensure data is always a string regardless of what the caller passed."""
        return str(v)


class AllowListResult(BaseModel):
    FileAllowList:     Optional[str] = None
    DomainAllowList:   Optional[str] = None
    FiletypeAllowList: Optional[str] = None