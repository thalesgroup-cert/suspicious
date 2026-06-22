"""
StopForumSpam (SFS) analyzer — scores an IP based on SFS reputation data.
"""
from __future__ import annotations
import logging
from typing import Any, Dict
from .base import BaseAnalyzer
from score_process.scoring.cortex_analyzers.response import get_level_score_confidence

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


class AnalyzerSFS(BaseAnalyzer):
    def process(self) -> Dict[str, Any]:
        response = super().process()
        try:
            taxonomies = self.summary.get("taxonomies", []) if self.summary else []
            full       = self.full or {}

            matching = next(
                (
                    t for t in taxonomies
                    if t.get("namespace") == "SFS"
                    and t.get("predicate") == "ip"
                ),
                None,
            )

            if matching is None:
                return response

            level     = str(matching.get("level", "info")).lower()
            raw_value = matching.get("value", "")
            score, confidence = get_level_score_confidence(level)

            response["level"]      = level
            response["score"]      = score
            response["confidence"] = confidence
            response["category"]   = ["SFS ip"]
            response["details"]    = {
                "SFS ip":    raw_value,
                "Full IP":   full.get("value",     ""),
                "Frequency": full.get("frequency",  0),
                "Appears":   full.get("appears",    False),
                "ASN":       full.get("asn",        ""),
                "Country":   full.get("country",    ""),
                "level":     level,
            }

        except Exception as exc:
            logger.error("[AnalyzerSFS] processing error: %s", exc, exc_info=True)

        return response