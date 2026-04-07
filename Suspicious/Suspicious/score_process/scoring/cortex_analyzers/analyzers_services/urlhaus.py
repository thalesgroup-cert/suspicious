# analyzers_services/urlhaus.py
"""
URLhaus analyzer — scores a URL based on the number of URLhaus sightings.
"""
from __future__ import annotations
import logging
import re
from typing import Any, Dict
from .base import BaseAnalyzer
from score_process.scoring.cortex_analyzers.base_helpers import get_level_score_confidence

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")

URLHAUS_THREAT_THRESHOLD = 0   # count > this → suspicious
_NO_RESULTS_SENTINEL     = "no results"


def _parse_urlhaus_count(value: str) -> int:
    """Extract the first integer from a URLhaus Search value string."""
    match = re.search(r"(\d+)", value)
    return int(match.group(1)) if match else 0


class AnalyzerURLhaus(BaseAnalyzer):
    def process(self) -> Dict[str, Any]:
        response = super().process()
        try:
            taxonomies = self.summary.get("taxonomies", []) if self.summary else []

            matching = next(
                (
                    t for t in taxonomies
                    if t.get("namespace") == "URLhaus"
                    and t.get("predicate") == "Search"
                ),
                None,
            )

            if matching is None:
                return response

            raw_value = str(matching.get("value", ""))

            if _NO_RESULTS_SENTINEL in raw_value.lower():
                level = "safe"
                count = 0
            else:
                count = _parse_urlhaus_count(raw_value)
                level = "suspicious" if count > URLHAUS_THREAT_THRESHOLD else "safe"

            score, confidence = get_level_score_confidence(level)

            response["level"]      = level
            response["score"]      = score
            response["confidence"] = confidence
            response["category"]   = ["URLhaus Search"]
            response["details"]    = {
                "URLhaus Search": raw_value,
                "count":          count,
                "level":          level,
            }

        except Exception as exc:
            logger.error("[AnalyzerURLhaus] processing error: %s", exc, exc_info=True)

        return response