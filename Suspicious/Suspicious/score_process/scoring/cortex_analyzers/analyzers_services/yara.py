# analyzers_services/yara.py
"""
YARA analyzer — scores a file based on the number of YARA rule matches.
"""
from __future__ import annotations
import logging
import re
from typing import Any, Dict
from .base import BaseAnalyzer
from score_process.scoring.cortex_analyzers.response import get_level_score_confidence

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")

KNOWN_LEVELS = frozenset({"safe", "info", "suspicious", "malicious"})


def _parse_yara_rule_count(value: str, analyzer_name: str) -> int:
    match = re.search(r"(\d+)", value)
    if not match:
        logger.warning("[%s] could not parse rule count from %r.", analyzer_name, value)
        return 0
    return int(match.group(1))


class AnalyzerYara(BaseAnalyzer):
    def process(self) -> Dict[str, Any]:
        response = super().process()
        try:
            taxonomies = self.summary.get("taxonomies", []) if self.summary else []
            full       = self.full or {}

            matching = next(
                (
                    t for t in taxonomies
                    if t.get("namespace") == "Yara"
                    and t.get("predicate") == "Match"
                ),
                None,
            )

            if matching is None:
                return response

            raw_value  = str(matching.get("value", ""))
            rule_count = _parse_yara_rule_count(raw_value, "AnalyzerYara")

            raw_level = str(matching.get("level", "safe")).lower()
            if raw_level not in KNOWN_LEVELS:
                logger.warning(
                    "[AnalyzerYara] unknown taxonomy level %r — defaulting to safe.",
                    raw_level,
                )
                raw_level = "safe"

            score, confidence = get_level_score_confidence(raw_level)

            response["level"]      = raw_level
            response["score"]      = score
            response["confidence"] = confidence
            response["category"]   = ["Yara Match"]
            response["details"]    = {
                "Yara Rule Matches": rule_count,
                "Yara Full Results": full.get("results", []),
                "level":             raw_level,
            }

        except Exception as exc:
            logger.error("[AnalyzerYara] processing error: %s", exc, exc_info=True)

        return response