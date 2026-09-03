"""Gather, per observable in a case's ObservableGroup, the SourceVerdict list
from its finished AnalyzerReports (newest report per analyzer)."""
from __future__ import annotations

from cortex_job.models import AnalyzerReport
from score_process.scoring.sources import source_verdict_from_report

_FIELD = {"URL": "url", "IP": "ip", "HASH": "hash", "DOMAIN": "domain"}


def observable_reports(case) -> list[tuple]:
    """Per group artifact: (art, obj, field, [reports]) with ONE AnalyzerReport
    query for the whole group, bucketed in Python by FK id. Reports are newest
    first. Shared by collect_observable_sources and assemble_observables so the
    detail/report paths don't issue one query per observable."""
    arts = []
    for art in case.observable_group.artifacts.select_related("url", "ip", "hash", "domain"):
        field = _FIELD[art.artifact_type]
        obj = getattr(art, field)
        if obj is not None:
            arts.append((art, obj, field))
    if not arts:
        return []

    from cortex_job.cortex_utils.case_targets import build_analyzer_report_filter

    q = build_analyzer_report_filter([(obj, field) for (_a, obj, field) in arts])
    reports = list(
        AnalyzerReport.objects.filter(q)
        .select_related("analyzer")
        .order_by("-creation_date")
    )

    buckets: dict[tuple, list] = {}
    for r in reports:
        for (_a, obj, field) in arts:
            if getattr(r, f"{field}_id") == obj.pk:
                buckets.setdefault((field, obj.pk), []).append(r)
                break

    return [(art, obj, field, buckets.get((field, obj.pk), [])) for (art, obj, field) in arts]


def collect_observable_sources(case):
    out = {}
    for art, obj, _field, reports in observable_reports(case):
        seen, verdicts = set(), []
        for r in reports:
            if r.analyzer_id in seen:
                continue
            seen.add(r.analyzer_id)
            verdicts.append(source_verdict_from_report(r))
        out[(art.artifact_type, obj.pk, obj)] = verdicts
    return out
