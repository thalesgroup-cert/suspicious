"""Lookyloo_Screenshot is a page-capture tool, not a reputation source.

Its Cortex summary taxonomy is
``{"level": "safe", "namespace": "Lookyloo", "predicate": "Screenshot", "value": "OK"}``
where ``OK`` means *the capture succeeded* — not that the site is safe.
DefaultTaxonomyParser reads that ``safe`` level as score 0 / confidence 100, i.e.
a strong clean vote — and Lookyloo runs on every url/domain/fqdn/ip observable
via type-dispatch, so that vote would land on every IOC and dilute real
verdicts on both roads.

This parser drops the verdict entirely: always ``info`` (analyzer added
context, no security opinion — same class as FileInfo's filetype tag), which
``score_process.scoring.sources`` maps to ``no-data`` for the categorical
engine. The screenshot bytes themselves are consumed separately by
``score_process.scoring.screenshots``.
"""
from __future__ import annotations

from typing import Any

from ..base import AnalyzerParser, AnalyzerManifest
from ..default import get_level_score_confidence
from ..result import AnalyzerResult


class LookylooScreenshotParser(AnalyzerParser):
    manifest = AnalyzerManifest(
        name="lookyloo_screenshot",
        cortex_names=("Lookyloo_Screenshot_1_0",),
        data_types=("url", "domain", "fqdn", "ip"),
    )

    def parse(self, summary: Any, full: Any) -> AnalyzerResult:
        full = full if isinstance(full, dict) else {}
        score, confidence = get_level_score_confidence("info")
        return AnalyzerResult(
            analyzer_name=self.analyzer_name,
            data=self.data_name,
            score=score,
            confidence=confidence,
            level="info",
            category=[],
            details={
                "capture_status": full.get("status"),
                "lookyloo_url": full.get("url"),
                "redirections": full.get("redirections"),
            },
        )
