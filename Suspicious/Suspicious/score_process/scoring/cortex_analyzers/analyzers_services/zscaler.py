# analyzers_services/zscaler.py
"""
Zscaler URL classification analyzer.
"""
from __future__ import annotations
import logging
from typing import Any, Dict
from .base import BaseAnalyzer
from score_process.scoring.cortex_analyzers.response import get_level_score_confidence

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


class AnalyzerZscaler(BaseAnalyzer):
    def process(self) -> Dict[str, Any]:
        response = super().process()
        try:
            taxonomies = self.summary.get("taxonomies", []) if self.summary else []
            full       = self.full or {}

            matching = next(
                (
                    t for t in taxonomies
                    if t.get("namespace") == "Zscaler"
                    and t.get("predicate") == "Classification"
                ),
                None,
            )

            if matching is None:
                return response

            raw_class = matching.get("value", "")
            class_val = str(raw_class).strip() if raw_class is not None else ""
            level     = str(matching.get("level", "safe")).lower()
            score, confidence = get_level_score_confidence(level)

            response["level"]      = level
            response["score"]      = score
            response["confidence"] = confidence
            response["category"]   = [class_val] if class_val else ["Zscaler"]
            response["details"]    = {
                "Zscaler Classification":                      class_val,
                "URL":                                         full.get("url", ""),
                "URL Classifications":                         full.get("urlClassifications", []),
                "URL Classifications with Security Alert":     full.get("urlClassificationsWithSecurityAlert", []),
                "level":                                       level,
            }

        except Exception as exc:
            logger.error("[AnalyzerZscaler] processing error: %s", exc, exc_info=True)

        return response