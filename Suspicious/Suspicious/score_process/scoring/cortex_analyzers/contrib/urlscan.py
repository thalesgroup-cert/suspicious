"""urlscan.io Search — not a verdict engine. Delegate level to taxonomy; enrich detail only."""
from __future__ import annotations

from typing import Any

from ..base import AnalyzerParser, AnalyzerManifest
from ..result import AnalyzerResult
from ..default import DefaultTaxonomyParser


class UrlscanSearchParser(AnalyzerParser):
    manifest = AnalyzerManifest(name="urlscan_search", cortex_names=("Urlscan_io_Search_0_1_1",),
                                data_types=("url", "domain", "hash", "ip"))

    def parse(self, summary: Any, full: Any) -> AnalyzerResult:
        base = DefaultTaxonomyParser(
            analyzer_name=self.analyzer_name, data=self.data,
            data_type=self.type, case_id=self.case_id,
        ).parse(summary, full)

        indicator = full.get("indicator", {}) if isinstance(full, dict) else {}
        results = indicator.get("results", []) if isinstance(indicator, dict) else []
        total = indicator.get("total", len(results)) if isinstance(indicator, dict) else 0
        urls = [r.get("page", {}).get("url") for r in results
                if isinstance(r, dict) and isinstance(r.get("page"), dict)][:5]

        base.details["urlscan_total"] = total
        base.details["urlscan_results"] = [u for u in urls if u]
        return base
