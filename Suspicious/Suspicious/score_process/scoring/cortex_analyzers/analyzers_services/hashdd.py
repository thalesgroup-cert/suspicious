# analyzers_services/hashdd.py
"""
Hashdd analyzer — scores a file hash based on its known-level result.
"""
from __future__ import annotations
import logging
from typing import Any, Dict
from .base import BaseAnalyzer
from score_process.scoring.cortex_analyzers.base_helpers import get_level_score_confidence

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")

HASHDD_UNKNOWN_VALUE = "unknown"


def _classify_hashdd_value(raw: str) -> str:
    """Return a severity level for a Hashdd knownlevel result string."""
    value = str(raw).strip().lower() if raw is not None else ""
    if value == HASHDD_UNKNOWN_VALUE:
        return "info"
    # "known" means the hash is in the database — not inherently suspicious.
    if value == "known":
        return "safe"
    # Any other value is unexpected; treat conservatively.
    return "info"


class AnalyzerHashdd(BaseAnalyzer):
    def process(self) -> Dict[str, Any]:
        response = super().process()
        try:
            taxonomies = self.summary.get("taxonomies", []) if self.summary else []

            matching = next(
                (
                    t for t in taxonomies
                    if t.get("namespace") == "Hashdd"
                    and t.get("predicate") == "knownlevel"
                ),
                None,
            )

            if matching is None:
                return response

            raw_value = matching.get("value", "")
            level     = _classify_hashdd_value(raw_value)
            score, confidence = get_level_score_confidence(level)

            response["level"]      = level
            response["score"]      = score
            response["confidence"] = confidence
            response["category"]   = ["Hashdd knownlevel"]
            response["details"]    = {
                "knownlevel": raw_value,
                "level":      level,
            }

        except Exception as exc:
            logger.error("[AnalyzerHashdd] processing error: %s", exc, exc_info=True)

        return response