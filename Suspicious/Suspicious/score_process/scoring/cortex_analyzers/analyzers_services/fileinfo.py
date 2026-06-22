"""
FileInfo analyzer — derives the highest-severity level across all
FileInfo taxonomy entries and extracts file type metadata.
"""
from __future__ import annotations
import logging
from typing import Any, Dict, Optional
from .base import BaseAnalyzer
from score_process.scoring.cortex_analyzers.response import get_level_score_confidence

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")

PRIORITY: Dict[str, int] = {
    "safe":      0,
    "info":      1,
    "suspicious": 2,
    "malicious": 3,
}

FILE_TYPE_PREDICATES = frozenset({"type", "filetype", "mime", "format"})


class AnalyzerFileinfo(BaseAnalyzer):
    def process(self) -> Dict[str, Any]:
        response   = super().process()
        best_level = "safe"          # default — no taxonomy = clean signal
        details:    Dict[str, Any] = {}
        file_type:  Optional[str]  = None

        try:
            taxonomies = self.summary.get("taxonomies", []) if self.summary else []

            for taxonomy in taxonomies:
                if taxonomy.get("namespace") != "FileInfo":
                    continue

                predicate = taxonomy.get("predicate", "unknown")
                value     = taxonomy.get("value", "")
                details[predicate] = value

                if predicate.lower() in FILE_TYPE_PREDICATES and isinstance(value, str):
                    file_type = value

                raw_level = taxonomy.get("level", "safe").lower()
                if raw_level not in PRIORITY:
                    logger.warning(
                        "[AnalyzerFileinfo] unknown level %r for predicate %r — treating as safe.",
                        raw_level, predicate,
                    )
                    raw_level = "safe"

                if PRIORITY[raw_level] > PRIORITY[best_level]:
                    best_level = raw_level

            score, confidence = get_level_score_confidence(best_level)

            response["level"]      = best_level
            response["score"]      = score
            response["confidence"] = confidence
            response["category"]   = [file_type] if file_type else ["FileInfo"]
            response["details"]    = details

        except Exception as exc:
            logger.error("[AnalyzerFileinfo] processing error: %s", exc, exc_info=True)

        return response