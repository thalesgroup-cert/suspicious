"""
CIRCL Hash Lookup analyzer — scores a file hash based on its known-hash
database lookup result.
"""
from __future__ import annotations

import logging
from typing import Any, Dict

from .base import BaseAnalyzer
from score_process.scoring.cortex_analyzers.response import get_level_score_confidence

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")

# ── Known result value sets ───────────────────────────────────────────────────
# "unkown" (sic) is the spelling Cortex actually returns in some versions of
# the CIRCLHashlookup analyzer — keep both variants so output from either
# version is handled correctly.
UNKNOWN_VALUES = frozenset({"unknown", "unkown"})
FOUND_VALUE    = "found"


def _classify_hashlookup_value(value: str) -> str:
    """Return a severity level for a CIRCLHashlookup result string."""
    normalised = value.lower()
    if normalised in UNKNOWN_VALUES:
        return "info"
    if normalised == FOUND_VALUE:
        return "suspicious"
    return "info"   # any other unexpected value defaults to info


class AnalyzerCIRCLHashLookup(BaseAnalyzer):
    def process(self) -> Dict[str, Any]:
        response = super().process()

        try:
            taxonomies = self.summary.get("taxonomies", []) if self.summary else []

            matching = next(
                (
                    t for t in taxonomies
                    if t.get("namespace") == "CIRCLHashlookup"
                    and t.get("predicate") == "Result"
                ),
                None,
            )

            if matching is None:
                return response

            raw_value = matching.get("value", "")
            # Coerce to string in case the API returns a non-string scalar
            value     = str(raw_value) if raw_value is not None else ""
            level     = _classify_hashlookup_value(value)
            score, confidence = get_level_score_confidence(level)

            response["level"]      = level
            response["score"]      = score
            response["confidence"] = confidence
            response["category"]   = ["CIRCLHashlookup Result"]
            response["details"]    = {
                "CIRCLHashlookup": value,
                "level":           level,
            }

        except Exception as exc:
            logger.error("[AnalyzerCIRCLHashLookup] processing error: %s", exc, exc_info=True)

        return response