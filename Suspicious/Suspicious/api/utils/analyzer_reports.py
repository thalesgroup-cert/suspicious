"""Case -> AnalyzerReport queryset, shared by the investigation-detail
serializer and the case screenshot endpoint.

Returns the reports before any Python-side de-duplication so callers can
chain further filters (`.exclude(screenshot_key="")`, ...). The
investigation detail still applies `_dedup_analyzer_reports` on top.
"""
from __future__ import annotations

from cortex_job.cortex_utils.case_targets import (
    build_analyzer_report_filter,
    collect_case_targets,
)
from cortex_job.models import AnalyzerReport

ANALYZER_REPORT_SELECT_RELATED = (
    "analyzer",
    "url",
    "domain",
    "mail",
    "hash",
    "file",
    "ip",
    "mail_body",
    "mail_header",
)


def reports_for_case(case):
    """Every AnalyzerReport filed against an artifact linked to ``case``.

    Ordered newest-first (`-creation_date, -pk`). Empty queryset when the
    case has no analyzable targets.
    """
    targets = collect_case_targets(case)
    if not targets:
        return AnalyzerReport.objects.none()

    return (
        AnalyzerReport.objects
        .filter(build_analyzer_report_filter(targets))
        .select_related(*ANALYZER_REPORT_SELECT_RELATED)
        .order_by("-creation_date", "-pk")
    )
