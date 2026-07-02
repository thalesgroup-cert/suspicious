"""
Typed models for the AI analyzer pipeline.

Uses Pydantic v2 throughout so all fields are validated on construction
and the objects are self-documenting.
"""
from __future__ import annotations

from typing import Any, Dict, List
from pydantic import BaseModel, ConfigDict, Field, field_validator


class MailReport(BaseModel):
    """Parsed output from the AI mail analyzer."""

    model_config = ConfigDict(from_attributes=True)

    malscore:                    float
    confidence:                  float
    classification:              str
    classification_probabilities: Dict[str, float] = Field(default_factory=dict)
    report:                      Dict[str, Any]    = Field(default_factory=dict)

    @field_validator("malscore", "confidence", mode="before")
    @classmethod
    def _clamp(cls, v: Any) -> float:
        return max(0.0, min(10.0, float(v)))


class SuspiciousMail(BaseModel):
    """A single mail entry retrieved from ChromaDB."""

    model_config = ConfigDict(from_attributes=True)

    mail_id:            str
    sender_domain:      str
    embedding:          List[float]   = Field(default_factory=list)
    report:             Dict[str, Any] = Field(default_factory=dict)
    suspicious_case_id: int

    def __str__(self) -> str:
        return "SuspiciousMail(case=%s domain=%s)" % (self.suspicious_case_id, self.sender_domain)


class PhishingCampaign(BaseModel):
    """A detected phishing campaign — a group of related dangerous mails."""

    model_config = ConfigDict(from_attributes=True)

    # Typed list instead of raw dicts — callers construct SuspiciousMail objects
    mails:      List[SuspiciousMail] = Field(default_factory=list)
    alert_id:   str                  = ""
    source_ref: str                  = ""
    metadatas:  List[Any]            = Field(default_factory=list)

    @property
    def case_ids(self) -> List[int]:
        """All suspicious case IDs present in this campaign."""
        return [m.suspicious_case_id for m in self.mails]