# analyzers_services/virustotal.py
"""
VirusTotal (VT) analyzer — scores a file or URL based on the
detection ratio across VT engines.
"""
from __future__ import annotations
import logging
import re
from typing import Any, Dict
from .base import BaseAnalyzer
from score_process.scoring.cortex_analyzers.base_helpers import get_level_score_confidence

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")

PRIORITY: Dict[str, int] = {
    "safe":       0,
    "info":       1,
    "suspicious": 2,
    "malicious":  3,
}
KNOWN_LEVELS = frozenset(PRIORITY)

VT_MALICIOUS_RATIO  = 0.5   # ratio >= this → malicious
VT_SUSPICIOUS_RATIO = 0.1   # ratio >= this → suspicious


def _parse_vt_ratio(value: str) -> float:
    """
    Parse a VirusTotal detection value into a 0.0-1.0 ratio.

    Accepts "N/D" fraction strings and raw integer percentages.
    Returns 0.0 on parse failure.
    """
    if "/" in value:
        try:
            num, den = value.split("/", 1)
            return int(num.strip()) / max(int(den.strip()), 1)
        except (ValueError, ZeroDivisionError):
            return 0.0
    match = re.search(r"(\d+)", value)
    return int(match.group(1)) / 100.0 if match else 0.0


def _classify_vt_ratio(ratio: float, taxonomy_level: str) -> str:
    """Return a severity level for a VT detection ratio."""
    if ratio >= VT_MALICIOUS_RATIO:
        return "malicious"
    if ratio >= VT_SUSPICIOUS_RATIO:
        return "suspicious"
    level = taxonomy_level.lower()
    return level if level in KNOWN_LEVELS else "safe"


class AnalyzerVT(BaseAnalyzer):
    def process(self) -> Dict[str, Any]:
        response   = super().process()
        best_level = "safe"      # no taxonomy = clean signal
        best_ratio = 0.0
        details:    Dict[str, Any] = {}

        try:
            taxonomies = self.summary.get("taxonomies", []) if self.summary else []

            for taxonomy in taxonomies:
                if taxonomy.get("namespace") != "VT" or taxonomy.get("predicate") != "GetReport":
                    continue

                raw_value      = str(taxonomy.get("value", ""))
                taxonomy_level = str(taxonomy.get("level", "safe"))
                ratio          = _parse_vt_ratio(raw_value)
                level          = _classify_vt_ratio(ratio, taxonomy_level)

                details[raw_value] = level

                if PRIORITY.get(level, 0) > PRIORITY.get(best_level, 0):
                    best_level = level
                    best_ratio = ratio

            score, confidence = get_level_score_confidence(best_level)

            response["level"]      = best_level
            response["score"]      = score
            response["confidence"] = confidence
            response["category"]   = ["VT GetReport"]
            response["details"]    = {
                "best_ratio":   best_ratio,
                "best_level":   best_level,
                "entries":      details,
            }

        except Exception as exc:
            logger.error("[AnalyzerVT] processing error: %s", exc, exc_info=True)

        return response