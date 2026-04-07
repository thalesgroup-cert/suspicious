# analyzers_services/abuseipdb.py
"""
AbuseIPDB analyzer — scores an IP based on the number of abuse reports.
"""
from __future__ import annotations

import logging
from typing import Any, Dict

from .base import BaseAnalyzer
from score_process.scoring.cortex_analyzers.response import get_level_score_confidence

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")

# ── Thresholds ────────────────────────────────────────────────────────────────
# Abuse report counts above which the level escalates.
# Tune these constants without touching the classification logic below.
ABUSEIPDB_MALICIOUS_THRESHOLD  = 10   # count > this  → malicious
ABUSEIPDB_SUSPICIOUS_THRESHOLD = 0    # count > this  → suspicious (else safe)


def _classify_abuse_count(count: int) -> str:
    """Return a severity level string for a given abuse-report count."""
    if count > ABUSEIPDB_MALICIOUS_THRESHOLD:
        return "malicious"
    if count > ABUSEIPDB_SUSPICIOUS_THRESHOLD:
        return "suspicious"
    return "safe"


class AnalyzerAbuseIPDB(BaseAnalyzer):
    def process(self) -> Dict[str, Any]:
        response = super().process()

        try:
            taxonomies = self.summary.get("taxonomies", []) if self.summary else []

            # Find the first AbuseIPDB Records taxonomy entry.
            # Using next() with a generator makes the intent explicit and
            # avoids the for/break idiom.
            matching = next(
                (
                    t for t in taxonomies
                    if t.get("namespace") == "AbuseIPDB"
                    and t.get("predicate") == "Records"
                ),
                None,
            )

            if matching is None:
                return response

            try:
                raw_count = int(matching.get("value", 0))
            except (TypeError, ValueError):
                logger.warning(
                    "[AnalyzerAbuseIPDB] non-integer Records value %r — defaulting to 0.",
                    matching.get("value"),
                )
                raw_count = 0

            # Clamp to non-negative — a negative value from a malformed API
            # response would otherwise be silently treated as "safe".
            count = max(0, raw_count)
            level = _classify_abuse_count(count)
            score, confidence = get_level_score_confidence(level)

            response["level"]      = level
            response["score"]      = score
            response["confidence"] = confidence
            response["category"]   = ["AbuseIPDB Records"]
            response["details"]    = {
                "Records": count,
                "level":   level,
            }

        except Exception as exc:
            logger.error("[AnalyzerAbuseIPDB] processing error: %s", exc, exc_info=True)

        return response