"""Cyberprotect ThreatScore — the upstream analyzer passes
`raw['threatscore']['level']` straight into the taxonomy. Cyberprotect's own
bands are safe / low / medium / high / critical (the score is a 0-100
percentage); only "safe" is a cortex taxonomy level, so DefaultTaxonomyParser
maps `high`/`critical` to an unknown level -> "info" -> no-data, silently
dropping a real malicious verdict.

This parser maps the bands explicitly. It also accepts a
safe/suspicious/malicious vocabulary in case the API returns that instead
(the public endpoint is IP-filtered and could not be verified live). Missing
`threatscore` (not in database, or an API error like the 403 "Blocked by IP
filtering" seen on unlicensed deployments) -> "info", unchanged.

NOTE: `Cyberprotect_ThreatScore_3_0` is non-functional without a licensed /
IP-allowlisted API account and has been removed from
deployment/scripts/enable-dev-analyzers.sh. This parser exists so that a
deployment which *does* have access gets the verdict scored correctly.
"""
from __future__ import annotations

from typing import Any

from ..base import AnalyzerParser, AnalyzerManifest
from ..result import AnalyzerResult
from ..default import get_level_score_confidence

_BAND_TO_LEVEL = {
    "safe": "safe",
    "low": "info",
    "medium": "suspicious", "suspicious": "suspicious",
    "high": "malicious", "critical": "malicious",
    "malicious": "malicious", "dangerous": "malicious",
    "info": "info",
}


class CyberprotectThreatScoreParser(AnalyzerParser):
    manifest = AnalyzerManifest(name="cyberprotect_threatscore",
                                cortex_names=("Cyberprotect_ThreatScore_3_0",),
                                data_types=("ip", "domain", "fqdn", "url", "hash"))

    def parse(self, summary: Any, full: Any) -> AnalyzerResult:
        ts = full.get("threatscore") if isinstance(full, dict) else None
        band = str(ts.get("level", "")).strip().lower() if isinstance(ts, dict) else ""
        level = _BAND_TO_LEVEL.get(band, "info")

        score, confidence = get_level_score_confidence(level)
        return AnalyzerResult(
            analyzer_name=self.analyzer_name, data=self.data_name,
            score=score, confidence=confidence, level=level,
            category=[f"ThreatScore {ts.get('value')} ({band})"] if isinstance(ts, dict) else ["no score"],
            details={"value": ts.get("value") if isinstance(ts, dict) else None, "band": band or None},
        )
