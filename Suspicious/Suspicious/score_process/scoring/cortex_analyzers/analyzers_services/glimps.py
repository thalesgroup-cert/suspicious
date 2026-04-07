# analyzers_services/glimps.py
"""
GMalware / GLIMPS analyzer — multi-factor scoring from sandbox output.
"""
from __future__ import annotations
import logging
from typing import Any, Dict, List, Optional
from .base import BaseAnalyzer
from score_process.scoring.cortex_analyzers.response import get_level_score_confidence

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")

# ── Weight thresholds ─────────────────────────────────────────────────────────
MALICIOUS_WEIGHT_HARD    = 5    # >= this  → malicious (regardless of other signals)
SUSPICIOUS_WEIGHT_FLOOR  = 3    # >= this  → suspicious when no hard malicious signal
SCORE_MALICIOUS_THRESHOLD  = 70
SCORE_SUSPICIOUS_THRESHOLD = 30

PRIORITY: Dict[str, int] = {
    "safe":       0,
    "info":       1,
    "suspicious": 2,
    "malicious":  3,
}


class AnalyzerGMalware(BaseAnalyzer):
    """
    Cortex analyzer service for GMalware / GLIMPS.

    Scoring principles:
      - Deterministic and explainable.
      - Multi-factor: no single field decides alone (except is_malware=True).
      - Conservative when signals conflict.
    """

    def process(self) -> Dict[str, Any]:
        response = super().process()

        try:
            summary = self.summary or {}
            full    = self.full    or {}

            # ── Summary taxonomy signal ───────────────────────────────────
            summary_taxonomy = next(
                (
                    t for t in summary.get("taxonomies", [])
                    if t.get("namespace") == "GMalware"
                    and t.get("predicate") == "Match"
                ),
                None,
            )
            summary_level: Optional[str] = (
                str(summary_taxonomy.get("level", "info")).lower()
                if summary_taxonomy else None
            )

            # ── Full-report signal extraction ─────────────────────────────
            is_malware  = full.get("is_malware")
            raw_score   = full.get("score")
            filetype    = full.get("filetype")
            file_count  = full.get("file_count", 0)
            files:  List[Any] = full.get("files", [])
            status  = full.get("status")
            done    = full.get("done")

            score = raw_score if isinstance(raw_score, (int, float)) else None
            if not isinstance(file_count, int):
                file_count = 0

            # ── Weighted voting ───────────────────────────────────────────
            malicious_weight:  float = 0.0
            suspicious_weight: float = 0.0
            info_weight:       float = 0.0

            if status is False or done is False:
                suspicious_weight += 2

            if is_malware is True:
                malicious_weight += 5
            elif is_malware is False:
                info_weight += 1

            if score is not None:
                if score >= SCORE_MALICIOUS_THRESHOLD:
                    malicious_weight += 4
                elif score >= SCORE_SUSPICIOUS_THRESHOLD:
                    suspicious_weight += 3
                elif score > 0:
                    suspicious_weight += 1
                else:
                    info_weight += 1

            for f in files:
                if f.get("is_malware") is True:
                    malicious_weight += 3
                elif f.get("is_malware") is False:
                    info_weight += 0.5   # partial credit — file is explicitly clean

            if isinstance(filetype, str):
                ft = filetype.lower()
                if any(x in ft for x in ("exe", "dll", "elf", "msi", "script")):
                    suspicious_weight += 2
                elif any(x in ft for x in ("pdf", "document", "image", "text")):
                    info_weight += 0.5

            if file_count > 1:
                suspicious_weight += 1

            if summary_level:
                if summary_level == "safe" and malicious_weight > 0:
                    suspicious_weight += 2
                elif summary_level in ("suspicious", "malicious") and malicious_weight == 0:
                    suspicious_weight += 1

            # ── Final level determination ─────────────────────────────────
            if malicious_weight >= MALICIOUS_WEIGHT_HARD:
                level = "malicious"
            elif malicious_weight > 0 or suspicious_weight >= SUSPICIOUS_WEIGHT_FLOOR:
                level = "suspicious"
            elif suspicious_weight > 0 or info_weight > 0:
                level = "info"
            else:
                level = "safe"

            score_out, confidence = get_level_score_confidence(level)

            response["level"]      = level
            response["score"]      = score_out
            response["confidence"] = confidence
            response["category"]   = ["GMalware"]
            response["details"]    = {
                "is_malware":       is_malware,
                "score":            score,
                "filetype":         filetype,
                "file_count":       file_count,
                "malicious_weight": malicious_weight,
                "suspicious_weight": suspicious_weight,
                "summary_level":    summary_level,
            }

        except Exception as exc:
            logger.error("[AnalyzerGMalware] processing error: %s", exc, exc_info=True)

        return response