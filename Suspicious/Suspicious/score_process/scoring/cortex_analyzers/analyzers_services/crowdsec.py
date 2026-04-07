# analyzers_services/crowdsec.py
"""
CrowdSec analyzer — scores an IP based on its CrowdSec threat level.
"""
from __future__ import annotations
import logging
from typing import Any, Dict
from .base import BaseAnalyzer
from score_process.scoring.cortex_analyzers.base_helpers import get_level_score_confidence

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


class AnalyzerCrowdsec(BaseAnalyzer):
    def process(self) -> Dict[str, Any]:
        response = super().process()
        try:
            taxonomies = self.summary.get("taxonomies", []) if self.summary else []

            matching = next(
                (
                    t for t in taxonomies
                    if t.get("namespace") == "Crowdsec"
                    and t.get("predicate") == "Threat"
                ),
                None,
            )

            if matching is None:
                return response

            raw_value = matching.get("value", "")
            level     = str(matching.get("level", "safe")).lower()

            response["level"]      = level
            response["score"], response["confidence"] = get_level_score_confidence(level)
            response["category"]   = ["Crowdsec Threat"]
            response["details"]    = {
                "Crowdsec Threat": raw_value,
                "level":           level,
            }

        except Exception as exc:
            logger.error("[AnalyzerCrowdsec] processing error: %s", exc, exc_info=True)

        return response