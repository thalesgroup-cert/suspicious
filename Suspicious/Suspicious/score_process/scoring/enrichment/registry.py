"""Dispatch an AnalyzerReport to its enrichment extractor, or None."""
from __future__ import annotations

import logging
from typing import Optional

from cortex_job.cortex_utils.report_target import analyzer_report_target_value
from score_process.scoring.enrichment import virustotal

logger = logging.getLogger(__name__)

# analyzer.name (lowercased) substring -> extractor callable(report_full, data_type, value)
_EXTRACTORS = (
    ("virustotal", virustotal.extract),
)


def enrich(report) -> Optional[dict]:
    name = (getattr(getattr(report, "analyzer", None), "name", "") or "").lower()
    for key, fn in _EXTRACTORS:
        if key in name:
            try:
                value = analyzer_report_target_value(report)
                return fn(report.report_full, report.type, value)
            except Exception as exc:
                logger.warning("enrichment for %s failed: %s", name, exc, exc_info=True)
                return None
    return None
