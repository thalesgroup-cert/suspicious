"""TeamCymruMHR — Team Cymru's Malware Hash Registry.

The upstream analyzer hardcodes its taxonomy level (`level = 'info'`, no branch)
and emits taxonomies at all only when a record exists — the real signal (that the
hash IS in a malware hash registry, plus the AV `detection_pct`) lives only in
the taxonomy *value*. DefaultTaxonomyParser reads the level, so a
confirmed-malware hash scored "info" -> "no-data" and contributed nothing to the
categorical engine. Same class of bug as SpamhausDBL (`3e6223cd`).

MHR only returns a record for samples its sensors saw flagged by AV engines, so
`status == "found_record"` is itself a positive detection -> malicious. A very
low detection percentage (a single fringe engine) is downgraded to suspicious.
No record / any other status is not evidence of "clean" for a niche registry ->
info / no-data, unchanged.

Full report shape (from TeamCymruMHR.py run()):
  found:     {"last_seen": "...", "detection_pct": "79", "status": "found_record"}
  no record: {"status": "No record found for <observable>"}
"""
from __future__ import annotations

from typing import Any, Optional

from ..base import AnalyzerParser, AnalyzerManifest
from ..result import AnalyzerResult
from ..default import get_level_score_confidence

# ponytail: fixed cutoff; tune against real MHR traffic if false positives show.
_SUSPICIOUS_BELOW_PCT = 15.0


def _to_pct(v: Any) -> Optional[float]:
    try:
        return float(str(v).strip().rstrip("%"))
    except (TypeError, ValueError):
        return None


class TeamCymruMhrParser(AnalyzerParser):
    manifest = AnalyzerManifest(name="team_cymru_mhr", cortex_names=("TeamCymruMHR_1_0",),
                                data_types=("hash", "file"))

    def parse(self, summary: Any, full: Any) -> AnalyzerResult:
        full = full if isinstance(full, dict) else {}

        if full.get("status") != "found_record":
            level, category = "info", ["No MHR record"]
        else:
            pct = _to_pct(full.get("detection_pct"))
            level = "suspicious" if pct is not None and pct < _SUSPICIOUS_BELOW_PCT else "malicious"
            category = [f"MHR detection {full.get('detection_pct')}%"]

        score, confidence = get_level_score_confidence(level)
        return AnalyzerResult(
            analyzer_name=self.analyzer_name, data=self.data_name,
            score=score, confidence=confidence, level=level, category=category,
            details={"status": full.get("status"), "last_seen": full.get("last_seen"),
                     "detection_pct": full.get("detection_pct")},
        )
