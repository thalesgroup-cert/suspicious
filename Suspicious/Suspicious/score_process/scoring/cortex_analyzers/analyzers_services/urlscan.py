# analyzers_services/urlscan.py
"""
Urlscan.io analyzer — scores a URL based on the number of urlscan results.
"""
from __future__ import annotations
import logging
import re
from typing import Any, Dict
from .base import BaseAnalyzer
from score_process.scoring.cortex_analyzers.base_helpers import get_level_score_confidence

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")

URLSCAN_THREAT_THRESHOLD = 0   # count > this → suspicious


def _parse_urlscan_count(value: str) -> int:
    match = re.search(r"(\d+)", value)
    return int(match.group(1)) if match else 0


class AnalyzerUrlscan(BaseAnalyzer):
    def process(self) -> Dict[str, Any]:
        response = super().process()
        try:
            taxonomies = self.summary.get("taxonomies", []) if self.summary else []

            matching = next(
                (
                    t for t in taxonomies
                    if t.get("namespace") == "urlscan.io"
                    and t.get("predicate") == "Search"
                ),
                None,
            )

            if matching is None:
                return response

            raw_value = str(matching.get("value", ""))
            count     = _parse_urlscan_count(raw_value)
            level     = "suspicious" if count > URLSCAN_THREAT_THRESHOLD else "safe"
            score, confidence = get_level_score_confidence(level)

            response["level"]      = level
            response["score"]      = score
            response["confidence"] = confidence
            response["category"]   = ["urlscan.io Search"]
            response["details"]    = {
                "urlscan.io Search Results": count,
                "raw":   raw_value,
                "level": level,
            }

        except Exception as exc:
            logger.error("[AnalyzerUrlscan] processing error: %s", exc, exc_info=True)

        return response