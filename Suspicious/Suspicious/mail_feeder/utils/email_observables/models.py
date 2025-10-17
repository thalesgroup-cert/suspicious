from typing import List, Dict, BinaryIO, Optional
from pydantic import BaseModel, Field, validator

class Artifact(BaseModel):
    dataType: str = Field(..., description="Type of the observable (e.g., url, domain, ip, etc.)")
    data: str = Field(..., description="Observable data value")
    tags: Optional[List[str]] = Field(default=None, description="Optional tags for the artifact")

    @validator("dataType", "data")
    def not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("dataType and data must be non-empty")
        return v


class ObservablesResult(BaseModel):
    artifacts: List[Artifact] = Field(default_factory=list)
    files: Dict[str, BinaryIO] = Field(default_factory=dict)
