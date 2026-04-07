# analyzers_services/otx.py
"""
OTX (AlienVault OTX) analyzer — scores based on number of OTX Pulses.
"""
from __future__ import annotations
import logging
from typing import Any, Dict
from .base import BaseAnalyzer
from score_process.scoring.cortex_analyzers.response import get_level_score_confidence

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")

OTX_MALICIOUS_PULSE_THRESHOLD  = 50   # >= this → malicious
OTX_SUSPICIOUS_PULSE_THRESHOLD = 10   # >= this → suspicious
# count > 0 and < SUSPICIOUS threshold → info
# count == 0 → safe


def _classify_otx_pulses(count: int) -> str:
    if count >= OTX_MALICIOUS_PULSE_THRESHOLD:
        return "malicious"
    if count >= OTX_SUSPICIOUS_PULSE_THRESHOLD:
        return "suspicious"
    if count > 0:
        return "info"
    return "safe"


class AnalyzerOTXQuery(BaseAnalyzer):
    def process(self) -> Dict[str, Any]:
        response = super().process()
        try:
            taxonomies = self.summary.get("taxonomies", []) if self.summary else []

            matching = next(
                (
                    t for t in taxonomies
                    if t.get("namespace") == "OTX"
                    and t.get("predicate") == "Pulses"
                ),
                None,
            )

            if matching is None:
                return response

            try:
                count = int(matching.get("value", 0))
            except (TypeError, ValueError):
                logger.warning("[AnalyzerOTXQuery] non-integer Pulses value %r — defaulting to 0.", matching.get("value"))
                count = 0

            level = _classify_otx_pulses(count)
            score, confidence = get_level_score_confidence(level)

            response["level"]      = level
            response["score"]      = score
            response["confidence"] = confidence
            response["category"]   = ["OTX Pulses"]
            response["details"]    = {
                "Pulses": count,
                "level":  level,
            }

        except Exception as exc:
            logger.error("[AnalyzerOTXQuery] processing error: %s", exc, exc_info=True)

        return response