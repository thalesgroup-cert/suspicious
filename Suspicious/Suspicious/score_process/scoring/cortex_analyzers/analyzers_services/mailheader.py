# analyzers_services/mailheader.py
"""
Mail Header analyzer — derives the highest-severity level across all
MailHeader taxonomy entries.
"""
from __future__ import annotations
import logging
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


class AnalyzerMailHeader(BaseAnalyzer):
    def process(self) -> Dict[str, Any]:
        response = super().process()
        try:
            taxonomies = self.summary.get("taxonomies", []) if self.summary else []
            full       = self.full or {}

            response.setdefault("details",  {})
            response.setdefault("category", [])

            for taxonomy in taxonomies:
                if taxonomy.get("namespace") != "MailHeader":
                    continue

                predicate = taxonomy.get("predicate")
                value     = taxonomy.get("value")
                raw_level = str(taxonomy.get("level", "info")).lower()

                if predicate:
                    response["details"][predicate] = value

                # Filter None values from category
                if value is not None and value not in response["category"]:
                    response["category"].append(value)

                if raw_level not in KNOWN_LEVELS:
                    logger.warning(
                        "[AnalyzerMailHeader] unknown level %r for predicate %r — skipping.",
                        raw_level, predicate,
                    )
                    continue

                current = response.get("level", "info")
                if PRIORITY.get(raw_level, 0) > PRIORITY.get(current, 0):
                    response["level"] = raw_level

            # Enrich with full-report fields
            response["details"].update({
                "full_malscore":    full.get("malscore"),
                "full_confidence":  full.get("confidence"),
                "full_malfamily":   full.get("malfamily"),
                "report":           full.get("report"),
            })

            # Derive score — default to "info" if no taxonomy set a level
            final_level = response.get("level", "info")
            response["score"], response["confidence"] = get_level_score_confidence(final_level)

        except Exception as exc:
            logger.error("[AnalyzerMailHeader] processing error: %s", exc, exc_info=True)

        return response