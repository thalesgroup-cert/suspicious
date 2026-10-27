"""VirusTotal GetReport — verdict from last_analysis_stats (v3) or positives/total (legacy)."""
from __future__ import annotations

import re
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


def _summary_counts(summary: Any) -> Optional[tuple[int, int]]:
    """(positives, total) from the analyzer's own "0/92" taxonomy, when the full report has no stats.

    The other taxonomies ("1 resolution(s)", "3 downloaded file(s)") are context, not detections:
    Cortex tags them suspicious or malicious, and the default parser would let them outvote 0/92.
    """
    if not isinstance(summary, dict):
        return None
    for tax in summary.get("taxonomies") or []:
        m = re.fullmatch(r"(\d+)/(\d+)", str((tax or {}).get("value", "")).strip())
        if m:
            return int(m[1]), int(m[2])
    return None


def _band(m: int, s: int, total: int, has_class: bool = False) -> tuple[str, int]:
    # VirusTotal's community reputation is deliberately not a signal: a few votes can sink a legitimate site.
    if m >= 2 or (m >= 1 and has_class):
        return "malicious", max(55, min(95, round(50 + 45 * m / max(total, 1))))
    if m == 1 or s >= 1:
        return "suspicious", 60
    return "safe", 90 if total >= 10 else 60


class VirusTotalGetReportParser(AnalyzerParser):
    manifest = AnalyzerManifest(name="virustotal_getreport", cortex_names=("VirusTotal_GetReport_3_1",),
                                data_types=("hash", "file", "url", "domain", "ip"))

    def parse(self, summary: Any, full: Any) -> AnalyzerResult:
        stats = _stats(full)
        positives = None
        if stats is None and isinstance(full, dict) and isinstance(full.get("results"), dict):
            positives = full["results"].get("positives")

        total_hint = None
        if stats is None and positives is None:
            counts = _summary_counts(summary)
            if counts is not None:
                positives, total_hint = counts

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
            total = total_hint if total_hint is not None else int(full["results"].get("total", 0) or 0)
            details = {"positives": malicious, "total": total}

        from score_process.scoring.enrichment.virustotal import extract as _vt_extract

        enr = _vt_extract(full, self.type)
        if enr is not None:
            m = int(enr.get("malicious_count", malicious) or 0)
            s = int(enr.get("suspicious_count", suspicious) or 0)
            total_e = int(enr.get("total", total) or 0)
            has_class = bool(enr.get("threat_label") or enr.get("threat_category"))

            level, confidence = _band(m, s, total_e, has_class)
            score, _ = get_level_score_confidence(level)   # keep the level->score column
            malicious, total = m, total_e                  # for the category string below
        else:
            # extraction unavailable — current behaviour verbatim
            if total_hint is not None:
                level, confidence = _band(malicious, suspicious, total)
                score, _ = get_level_score_confidence(level)
            else:
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
