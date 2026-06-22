"""
DShield analyzer — scores an IP based on DShield count/attacks/threatfeed data.
"""
from __future__ import annotations
import logging
import re
from typing import Any, Dict, Optional, Tuple
from .base import BaseAnalyzer
from score_process.scoring.cortex_analyzers.response import get_level_score_confidence

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")

_DSHIELD_SCORE_PATTERN = re.compile(
    r"(\d+)\s*count\(s\)\s*/\s*"
    r"(\d+)\s*attack\(s\)\s*/\s*"
    r"(\d+)\s*threatfeed\(s\)",
    re.IGNORECASE,
)


def _parse_dshield_score(
    value: str,
) -> Optional[Tuple[int, int, int]]:
    """
    Parse "N count(s) / M attack(s) / P threatfeed(s)" into (N, M, P).
    Returns None when the value does not match the expected format.
    """
    match = _DSHIELD_SCORE_PATTERN.search(value)
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


class AnalyzerDShield(BaseAnalyzer):
    def process(self) -> Dict[str, Any]:
        response = super().process()
        try:
            taxonomies = self.summary.get("taxonomies", []) if self.summary else []
            full       = self.full or {}

            matching = next(
                (
                    t for t in taxonomies
                    if t.get("namespace") == "DShield"
                    and t.get("predicate") == "Score"
                ),
                None,
            )

            if matching is None:
                return response

            raw_value = str(matching.get("value", ""))
            level     = str(matching.get("level", "safe")).lower()

            parsed = _parse_dshield_score(raw_value)
            if parsed is None:
                logger.warning(
                    "[AnalyzerDShield] could not parse score string %r — "
                    "level from taxonomy will still be used.",
                    raw_value,
                )
                count = attacks = threatfeeds = None
            else:
                count, attacks, threatfeeds = parsed

            score, confidence = get_level_score_confidence(level)

            response["level"]      = level
            response["score"]      = score
            response["confidence"] = confidence
            response["category"]   = ["DShield Score"]
            response["details"]    = {
                "DShield Score":     raw_value,
                "level":             level,
                # Parsed fields — None when the value string could not be parsed
                "count":             count      if count      is not None else full.get("count", 0),
                "attacks":           attacks    if attacks    is not None else full.get("attacks", 0),
                "threatfeeds_count": threatfeeds if threatfeeds is not None else full.get("threatfeedscount", 0),
                # Additional context from the full report
                "IP":                full.get("ip", ""),
                "Reputation":        full.get("reputation", ""),
            }

        except Exception as exc:
            logger.error("[AnalyzerDShield] processing error: %s", exc, exc_info=True)

        return response