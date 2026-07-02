"""
Google Safe Browsing analyzer — scores a URL based on the number of
Safe Browsing hits reported by Google.
"""
from __future__ import annotations
import logging
import re
from typing import Any, Dict, Optional
from .base import BaseAnalyzer
from score_process.scoring.cortex_analyzers.response import get_level_score_confidence

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")

THREAT_COUNT_THRESHOLD = 0     # count > this → suspicious


def _parse_threat_count(value: str, analyzer_name: str) -> Optional[int]:
    """Extract the first integer from the Safe Browsing value string."""
    match = re.search(r"(\d+)", value)
    if match:
        return int(match.group(1))
    logger.warning("[%s] could not parse threat count from %r.", analyzer_name, value)
    return None


class AnalyzerGoogleSafeBrowsing(BaseAnalyzer):
    def process(self) -> Dict[str, Any]:
        response = super().process()
        try:
            taxonomies = self.summary.get("taxonomies", []) if self.summary else []

            matching = next(
                (
                    t for t in taxonomies
                    if t.get("namespace") == "Google"
                    and t.get("predicate") == "Safebrowsing"
                ),
                None,
            )

            if matching is None:
                return response

            raw_value = str(matching.get("value", ""))
            count     = _parse_threat_count(raw_value, "AnalyzerGoogleSafeBrowsing")
            level     = "suspicious" if (count is not None and count > THREAT_COUNT_THRESHOLD) else "safe"
            score, confidence = get_level_score_confidence(level)

            response["level"]      = level
            response["score"]      = score
            response["confidence"] = confidence
            response["category"]   = ["Google Safebrowsing"]
            response["details"]    = {
                "Safebrowsing":  raw_value,
                "threat_count":  count,
                "level":         level,
            }

        except Exception as exc:
            logger.error("[AnalyzerGoogleSafeBrowsing] processing error: %s", exc, exc_info=True)

        return response