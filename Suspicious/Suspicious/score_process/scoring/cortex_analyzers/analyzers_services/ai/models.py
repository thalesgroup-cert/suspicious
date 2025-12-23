from dataclasses import dataclass, field
from typing import Dict, Any, List

@dataclass
class MailReport:
    malscore: float
    confidence: float
    classification: str
    classification_probabilities: Dict[str, float] = field(default_factory=dict)
    report: Dict[str, Any] = field(default_factory=dict)

@dataclass
class PhishingCampaign:
    mails: List[Dict[str, Any]] = field(default_factory=list)
    alert_id: str = ""
    source_ref: str = ""

@dataclass
class SuspiciousMail:
    mail_id: str
    sender_domain: str
    embedding: List[float]
    report: Dict[str, Any]
    suspicious_case_id: int
