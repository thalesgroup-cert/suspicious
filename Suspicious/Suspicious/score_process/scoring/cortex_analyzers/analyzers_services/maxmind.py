"""
MaxMind GeoIP analyzer — enriches an IP with geographic context.
"""
from __future__ import annotations
import logging
from typing import Any, Dict
from .base import BaseAnalyzer
from score_process.scoring.cortex_analyzers.response import get_level_score_confidence

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


class AnalyzerMaxMind(BaseAnalyzer):
    def process(self) -> Dict[str, Any]:
        response = super().process()
        try:
            taxonomies = self.summary.get("taxonomies", []) if self.summary else []

            matching = next(
                (
                    t for t in taxonomies
                    if t.get("namespace") == "MaxMind"
                    and t.get("predicate") == "Location"
                ),
                None,
            )

            if matching is None:
                return response

            level     = str(matching.get("level", "info")).lower()
            raw_value = matching.get("value", "")
            full      = self.full or {}

            details: Dict[str, Any] = {"MaxMind Location": raw_value}
            details.update({
                "City":                 full.get("city",                 {}),
                "Continent":            full.get("continent",            {}),
                "Country":              full.get("country",              {}),
                "Location":             full.get("location",             {}),
                "Registered Country":   full.get("registered_country",   {}),
                "Represented Country":  full.get("represented_country",  {}),
                "Subdivisions":         full.get("subdivisions",         {}),
                "Traits":               full.get("traits",               {}),
            })

            response["level"]      = level
            response["score"], response["confidence"] = get_level_score_confidence(level)
            response["category"]   = ["MaxMind Location"]
            response["details"]    = details

        except Exception as exc:
            logger.error("[AnalyzerMaxMind] processing error: %s", exc, exc_info=True)

        return response