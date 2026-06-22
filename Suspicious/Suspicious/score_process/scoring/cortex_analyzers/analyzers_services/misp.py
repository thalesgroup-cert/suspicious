"""
MISP analyzer — scores based on the number of MISP event matches.
"""
from __future__ import annotations
import logging
import re
from typing import Any, Dict
from .base import BaseAnalyzer
from score_process.scoring.cortex_analyzers.response import get_level_score_confidence

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")

MISP_MALICIOUS_EVENT_THRESHOLD  = 4   # >= this → malicious
# count > 0 and < MALICIOUS threshold → suspicious
# count == 0 → safe

_MISP_MISSING_LEVEL_SENTINEL = "0"   # Cortex returns "0" when no level is set


def _classify_misp_count(count: int) -> str:
    if count >= MISP_MALICIOUS_EVENT_THRESHOLD:
        return "malicious"
    if count > 0:
        return "suspicious"
    return "safe"


class AnalyzerMISP(BaseAnalyzer):
    def process(self) -> Dict[str, Any]:
        response = super().process()
        try:
            taxonomies = self.summary.get("taxonomies", []) if self.summary else []

            matching = next(
                (
                    t for t in taxonomies
                    if t.get("namespace") == "MISP"
                    and t.get("predicate") == "Search"
                ),
                None,
            )

            if matching is None:
                return response

            raw_value = str(matching.get("value", "0"))
            match     = re.search(r"(\d+)", raw_value)
            if match:
                count = int(match.group(1))
            else:
                logger.warning(
                    "[AnalyzerMISP] could not parse event count from %r — defaulting to 0.",
                    raw_value,
                )
                count = 0

            taxonomy_level = str(matching.get("level", _MISP_MISSING_LEVEL_SENTINEL))
            if taxonomy_level == _MISP_MISSING_LEVEL_SENTINEL:
                level = _classify_misp_count(count)
            else:
                level = taxonomy_level.lower()

            score, confidence = get_level_score_confidence(level)

            response["level"]      = level
            response["score"]      = score
            response["confidence"] = confidence
            response["category"]   = ["MISP Events"]
            response["details"]    = {
                "MISP Events": count,
                "level":       level,
            }

        except Exception as exc:
            logger.error("[AnalyzerMISP] processing error: %s", exc, exc_info=True)

        return response