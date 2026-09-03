"""Gather, per observable in a case's ObservableGroup, the SourceVerdict list
from its finished AnalyzerReports (newest report per analyzer)."""
from __future__ import annotations

from cortex_job.models import AnalyzerReport
from score_process.scoring.sources import source_verdict_from_report

_FIELD = {"URL": "url", "IP": "ip", "HASH": "hash", "DOMAIN": "domain"}


def collect_observable_sources(case):
    out = {}
    for art in case.observable_group.artifacts.select_related("url", "ip", "hash", "domain"):
        field = _FIELD[art.artifact_type]
        obj = getattr(art, field)
        if obj is None:
            continue
        reports = (
            AnalyzerReport.objects.filter(**{field: obj})
            .select_related("analyzer")
            .order_by("-creation_date")
        )
        seen, verdicts = set(), []
        for r in reports:
            if r.analyzer_id in seen:
                continue
            seen.add(r.analyzer_id)
            verdicts.append(source_verdict_from_report(r))
        out[(art.artifact_type, obj.pk, obj)] = verdicts
    return out
