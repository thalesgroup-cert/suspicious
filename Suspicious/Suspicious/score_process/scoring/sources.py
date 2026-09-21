"""Map an AnalyzerReport to a categorical SourceVerdict for the IOC engine.

No ORM writes or queries. Pure translation of the parser's categorical
``level`` plus ``status`` into the vote the observable engine consumes.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

_LEVEL_TO_VERDICT = {
    "malicious": "malicious",
    "dangerous": "malicious",
    "suspicious": "suspicious",
    "safe": "clean",
}


@dataclass(frozen=True)
class SourceVerdict:
    name: str
    tier: int
    weight: float
    verdict: str            # "malicious" | "suspicious" | "clean" | "no-data"
    confidence: Optional[int]
    failed: bool
    evidence: str


def source_verdict_from_report(report) -> SourceVerdict:
    analyzer = report.analyzer
    status = (report.status or "").strip()
    failed = status == "Failure"

    if status != "Success":
        verdict = "no-data"
    else:
        verdict = _LEVEL_TO_VERDICT.get((report.level or "").strip().lower(), "no-data")

    category = report.category or ""
    evidence = category.split(",")[0].strip() if category else ""

    conf = getattr(report, "confidence", None)
    confidence = int(conf) if isinstance(conf, (int, float)) and not isinstance(conf, bool) and conf else None

    return SourceVerdict(
        name=analyzer.name,
        tier=int(getattr(analyzer, "tier", 3)),
        weight=float(getattr(analyzer, "weight", 0.2)),
        verdict=verdict,
        confidence=confidence,
        failed=failed,
        evidence=evidence,
    )
