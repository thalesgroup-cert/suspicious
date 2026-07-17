"""Zscaler URL classification — verdict lives in the security-alert list, not the taxonomy."""
from __future__ import annotations

from typing import Any

from ..base import AnalyzerParser, AnalyzerManifest
from ..result import AnalyzerResult
from ..default import get_level_score_confidence


class ZscalerParser(AnalyzerParser):
    manifest = AnalyzerManifest(name="zscaler", cortex_names=("Zscaler_1_3",), data_types=("url",))

    def parse(self, summary: Any, full: Any) -> AnalyzerResult:
        full = full if isinstance(full, dict) else {}
        alerts = full.get("urlClassificationsWithSecurityAlert") or []
        classes = full.get("urlClassifications") or []

        if alerts:
            level, category = "malicious", list(alerts)
        else:
            level, category = "info", list(classes)

        score, confidence = get_level_score_confidence(level)
        return AnalyzerResult(
            analyzer_name=self.analyzer_name, data=self.data_name,
            score=score, confidence=confidence, level=level,
            category=category or ["Zscaler"],
            details={"urlClassifications": classes, "urlClassificationsWithSecurityAlert": alerts},
        )
