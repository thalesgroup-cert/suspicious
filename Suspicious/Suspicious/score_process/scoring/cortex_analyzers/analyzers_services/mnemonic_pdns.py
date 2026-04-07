# analyzers_services/mnemonic_pdns.py
"""
Mnemonic passive DNS (PDNS) analyzer.
"""
from __future__ import annotations
import logging
from typing import Any, Dict
from .base import BaseAnalyzer
from score_process.scoring.cortex_analyzers.response import get_level_score_confidence

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


class AnalyzerMN_PDNS(BaseAnalyzer):
    def process(self) -> Dict[str, Any]:
        response = super().process()
        try:
            taxonomies = self.summary.get("taxonomies", []) if self.summary else []
            full       = self.full or {}

            matching = next(
                (
                    t for t in taxonomies
                    if t.get("namespace") == "MN_PDNS"
                    and t.get("predicate") == "Public"
                ),
                None,
            )

            if matching is None:
                return response

            level     = str(matching.get("level", "info")).lower()
            raw_value = matching.get("value", 0)
            findings  = full.get("findings", {})
            score, confidence = get_level_score_confidence(level)

            response["level"]      = level
            response["score"]      = score
            response["confidence"] = confidence
            response["category"]   = ["MN_PDNS Public"]
            response["details"]    = {
                "MN_PDNS Public Value": raw_value,
                "Findings Count":       findings.get("count", 0),
                "Data":                 findings.get("data",  []),
                "level":                level,
            }

        except Exception as exc:
            logger.error("[AnalyzerMN_PDNS] processing error: %s", exc, exc_info=True)

        return response