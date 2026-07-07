"""VirusTotal GetReport — verdict from last_analysis_stats (v3) or positives/total (legacy)."""
from __future__ import annotations

from typing import Any, Optional

from ..base import AnalyzerParser, AnalyzerManifest
from ..result import AnalyzerResult
from ..default import get_level_score_confidence, DefaultTaxonomyParser


def _stats(full: Any) -> Optional[dict]:
    """Return the {malicious, suspicious, harmless, undetected} dict, v3 or top-level."""
    if not isinstance(full, dict):
        return None
    res = full.get("results")
    if isinstance(res, dict):
        attrs = res.get("data", {})
        if isinstance(attrs, dict):
            stats = attrs.get("attributes", {}).get("last_analysis_stats")
            if isinstance(stats, dict):
                return stats
        if isinstance(res.get("last_analysis_stats"), dict):
            return res["last_analysis_stats"]
    return None


class VirusTotalGetReportParser(AnalyzerParser):
    manifest = AnalyzerManifest(name="virustotal_getreport", cortex_names=("VirusTotal_GetReport_3_1",),
                                data_types=("hash", "file", "url", "domain", "ip"))

    def parse(self, summary: Any, full: Any) -> AnalyzerResult:
        stats = _stats(full)
        positives = None
        if stats is None and isinstance(full, dict) and isinstance(full.get("results"), dict):
            positives = full["results"].get("positives")

        if stats is None and positives is None:
            # No engine data — honour the taxonomy.
            return DefaultTaxonomyParser(
                analyzer_name=self.analyzer_name, data=self.data,
                data_type=self.type, case_id=self.case_id,
            ).parse(summary, full)

        if stats is not None:
            malicious = int(stats.get("malicious", 0) or 0)
            suspicious = int(stats.get("suspicious", 0) or 0)
            total = sum(int(v or 0) for v in stats.values())
            details = {"last_analysis_stats": stats}
        else:  # legacy
            malicious, suspicious = int(positives or 0), 0
            total = int(full["results"].get("total", 0) or 0)
            details = {"positives": malicious, "total": total}

        if malicious > 0:
            level = "malicious"
        elif suspicious > 0:
            level = "suspicious"
        else:
            level = "safe"

        score, confidence = get_level_score_confidence(level)
        return AnalyzerResult(
            analyzer_name=self.analyzer_name, data=self.data_name,
            score=score, confidence=confidence, level=level,
            category=[f"{malicious}/{total} engines"], details=details,
        )
