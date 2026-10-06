"""Structured, render-agnostic explanation of a case verdict.
Read-only over the scoring output — carries no verdict logic."""
from __future__ import annotations

from dataclasses import dataclass, asdict


@dataclass(frozen=True)
class SourceLine:
    name: str
    tier: int          # 1 authoritative / 2 strong / 3 contextual / 0 untiered
    verdict: str        # malicious | suspicious | clean | no-data | failed
    counted: bool       # did this source feed the decisive rule?
    note: str = ""


@dataclass(frozen=True)
class VerdictExplanation:
    band: str
    confidence: int
    decisive_rule: str
    analyst_paragraph: str
    reporter_paragraph: str
    confidence_reading: str
    sources: tuple[SourceLine, ...] = ()

    def to_dict(self) -> dict:
        d = asdict(self)
        d["sources"] = [asdict(s) for s in self.sources]
        return d
