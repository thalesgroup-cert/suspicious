"""Parser for AI_Mail_Analyzer (classification/malscore/confidence shape).

Pure score extraction. Campaign detection and the TheHive push are not done here:
they run once per case at finalisation (case_handler.campaigns) and reach
connectors through the ``campaign_updated`` event.
"""
from __future__ import annotations

import logging
from typing import Any

from ..base import AnalyzerParser, AnalyzerManifest
from ..result import AnalyzerResult

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")

class AiMailParser(AnalyzerParser):
    manifest = AnalyzerManifest(
        name="ai_mail",
        cortex_names=("AI_Mail_Analyzer", "AI_Mail_Analyzer_1_4", "AI_Mail_Analyzer_2_0"),
        data_types=("file",),
    )

    def parse(self, summary: Any, full: Any) -> AnalyzerResult:
        self.summary, self.full = summary, full
        score, confidence, level, details = 5, 0, "info", {}

        if isinstance(summary, dict):
            try:
                score = round(float(summary.get("malscore", 5)))
                confidence = round(float(summary.get("confidence", 0)) * 100)
                level = str(summary.get("classification", "info")).lower()
            except (TypeError, ValueError) as exc:
                logger.warning("[ai_mail] score parse failed: %s", exc)

        if isinstance(full, dict):
            for key in ("classification_probabilities", "report",
                        "malscore", "confidence", "classification"):
                if key in full:
                    details[key] = full[key]

        result = AnalyzerResult(
            analyzer_name=self.analyzer_name, data=self.data_name,
            score=score, confidence=confidence, category=[level],
            level=level, details=details,
        )
        return result
