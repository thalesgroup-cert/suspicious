"""MISP — escalate on matched events; level from max threat_level_id."""
from __future__ import annotations

from typing import Any

from ..base import AnalyzerParser, AnalyzerManifest
from ..result import AnalyzerResult
from ..default import get_level_score_confidence, DefaultTaxonomyParser

# MISP threat_level_id → our level. 1=High, 2=Medium, 3=Low, 4=Undefined.
THREAT_LEVEL = {1: "malicious", 2: "suspicious", 3: "suspicious", 4: "info"}


def _events(full: Any) -> list:
    if not isinstance(full, dict):
        return []
    out = []
    for block in full.get("results", []) or []:
        if isinstance(block, dict):
            out.extend(e for e in (block.get("result") or []) if isinstance(e, dict))
    return out


class MispParser(AnalyzerParser):
    manifest = AnalyzerManifest(name="misp", cortex_names=("MISP_2_1",),
                                data_types=("hash", "file", "url", "domain", "ip", "mail"))

    def parse(self, summary: Any, full: Any) -> AnalyzerResult:
        events = _events(full)
        if not events:
            return DefaultTaxonomyParser(
                analyzer_name=self.analyzer_name, data=self.data,
                data_type=self.type, case_id=self.case_id,
            ).parse(summary, full)

        # Most severe = lowest threat_level_id (1 is highest threat).
        ids = []
        for e in events:
            try:
                ids.append(int(e.get("threat_level_id", 4)))
            except (TypeError, ValueError):
                ids.append(4)
        level = THREAT_LEVEL.get(min(ids), "info")

        score, confidence = get_level_score_confidence(level)
        names = [e.get("info") for e in events if e.get("info")]
        return AnalyzerResult(
            analyzer_name=self.analyzer_name, data=self.data_name,
            score=score, confidence=confidence, level=level,
            category=names or [f"{len(events)} MISP events"],
            details={"event_count": len(events),
                     "event_ids": [e.get("id") for e in events],
                     "threat_level_ids": ids},
        )
