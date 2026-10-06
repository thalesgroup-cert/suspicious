"""ThreatMiner — free OSINT context (passive DNS, related samples, WHOIS, URIs).

The upstream analyzer's summary() has *inverted* logic: it defaults the taxonomy
level to "suspicious" and only drops to "safe" when the API returns any rows
(`level = 'suspicious'`; `if len(raw["results"]) != 0: level = "safe"`). So an
indicator ThreatMiner has never seen — or that its notoriously flaky API just
failed to return — gets a phantom "suspicious" vote, and one it happens to have a
passive-DNS row for gets an unearned "safe" vote. In the categorical engine a
lone Tier-3 "suspicious" forces the whole observable to Suspicious
(observable_engine Rule 3).

ThreatMiner has no verdict to give — it is raw enrichment — so this parser always
maps to "info" (-> no-data) and just carries the row count for the analyst.
"""
from __future__ import annotations

from typing import Any

from ..base import AnalyzerParser, AnalyzerManifest
from ..result import AnalyzerResult
from ..default import get_level_score_confidence


class ThreatMinerParser(AnalyzerParser):
    manifest = AnalyzerManifest(name="threatminer", cortex_names=("ThreatMiner_1_0",),
                                data_types=("ip", "domain", "fqdn", "hash", "file"))

    def parse(self, summary: Any, full: Any) -> AnalyzerResult:
        full = full if isinstance(full, dict) else {}
        results = full.get("results")
        n = len(results) if isinstance(results, list) else 0

        score, confidence = get_level_score_confidence("info")
        return AnalyzerResult(
            analyzer_name=self.analyzer_name, data=self.data_name,
            score=score, confidence=confidence, level="info",
            category=[f"{n} ThreatMiner record(s)"] if n else ["No ThreatMiner data"],
            details={"result_count": n, "status_message": full.get("status_message")},
        )
