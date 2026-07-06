"""Default parser for taxonomy/results-shaped Cortex output (the common case)."""
from __future__ import annotations

import logging
from typing import Any

from .base import AnalyzerParser, AnalyzerManifest
from .result import AnalyzerResult

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")

SEVERITY_ORDER = {"safe": 0, "info": 1, "suspicious": 2, "malicious": 3, "dangerous": 3}


def get_level_score_confidence(level: str) -> tuple[int, int]:
    match level:
        case "malicious" | "dangerous": return 10, 100
        case "suspicious":              return 7, 70
        case "info":                    return 5, 50
        case "safe":                    return 0, 100
        case _:                         return 0, 0


class DefaultTaxonomyParser(AnalyzerParser):
    manifest = AnalyzerManifest(name="default", cortex_names=())

    def parse(self, summary: Any, full: Any) -> AnalyzerResult:
        level, category, details, score, confidence = "info", [], {}, 5, 50

        if isinstance(summary, dict) and summary.get("taxonomies"):
            # Take the highest-severity taxonomy level, seeded from the first
            # taxonomy (not the "info" default) so a genuinely `safe` verdict —
            # e.g. GoogleSafebrowsing "0 match" — is honoured instead of being
            # floored to info.
            tax_level = None
            for tax in summary["taxonomies"]:
                lvl = str(tax.get("level", "info")).lower()
                if tax_level is None or SEVERITY_ORDER.get(lvl, 1) > SEVERITY_ORDER.get(tax_level, 1):
                    tax_level = lvl
                val = tax.get("value")
                if val and val not in category:
                    category.append(val)
                if tax.get("predicate"):
                    details[tax["predicate"]] = val
            level = tax_level or "info"
            score, confidence = get_level_score_confidence(level)

        if isinstance(full, dict) and isinstance(full.get("results"), list):
            for el in full["results"]:
                if isinstance(el, dict):
                    threat = el.get("threat")
                    if threat and threat not in category:
                        category.append(threat)
                    for k, v in el.items():
                        details.setdefault(k, v)
                else:
                    category.append(el)
                    details.setdefault("raw_results", []).append(el)

        return AnalyzerResult(
            analyzer_name=self.analyzer_name, data=self.data_name,
            score=score, confidence=confidence, category=category,
            level=level, details=details,
        )
