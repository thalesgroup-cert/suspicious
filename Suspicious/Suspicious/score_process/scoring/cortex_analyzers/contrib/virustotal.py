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
            inner = attrs.get("attributes")
            if isinstance(inner, dict):
                stats = inner.get("last_analysis_stats")
                if isinstance(stats, dict):
                    return stats
        flat = res.get("attributes")
        if isinstance(flat, dict) and isinstance(flat.get("last_analysis_stats"), dict):
            return flat["last_analysis_stats"]
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
            return DefaultTaxonomyParser(
                analyzer_name=self.analyzer_name, data=self.data,
                data_type=self.type, case_id=self.case_id,
            ).parse(summary, full)

        if stats is not None:
            malicious = int(stats.get("malicious", 0) or 0)
            suspicious = int(stats.get("suspicious", 0) or 0)
            total = sum(int(v or 0) for v in stats.values())
            details = {"last_analysis_stats": stats}
        else:
            malicious, suspicious = int(positives or 0), 0
            total = int(full["results"].get("total", 0) or 0)
            details = {"positives": malicious, "total": total}

        from score_process.scoring.enrichment.virustotal import extract as _vt_extract

        enr = _vt_extract(full, self.type)
        if enr is not None:
            m = int(enr.get("malicious_count", malicious) or 0)
            s = int(enr.get("suspicious_count", suspicious) or 0)
            total_e = int(enr.get("total", total) or 0)
            reputation = enr.get("reputation")
            has_class = bool(enr.get("threat_label") or enr.get("threat_category"))

            if m >= 2 or (m >= 1 and has_class):
                level = "malicious"
                confidence = max(55, min(95, round(50 + 45 * m / max(total_e, 1))))
            elif m == 1 or s >= 1 or (isinstance(reputation, (int, float)) and reputation <= -25 and m == 0):
                level = "suspicious"
                confidence = 60
            else:
                level = "safe"
                confidence = 90 if total_e >= 10 else 60
            score, _ = get_level_score_confidence(level)   # keep the level->score column
            malicious, total = m, total_e                  # for the category string below
        else:
            # extraction unavailable — current behaviour verbatim
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
