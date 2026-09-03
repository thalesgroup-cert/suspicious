"""Per-observable report rows for an ObservableGroup case.

Shared by the investigation detail API (Task 9) and the downloadable report
(Task 11): value, type, computed categorical verdict, and every trusted
source's vote plus its full analyzer report.
"""
from __future__ import annotations

from cortex_job.models import AnalyzerReport
from score_process.scoring.observable_engine import score_observable
from score_process.scoring.sources import source_verdict_from_report

_FIELD = {"URL": "url", "IP": "ip", "HASH": "hash", "DOMAIN": "domain"}


def assemble_observables(case) -> list[dict]:
    """Per-observable rows for an ObservableGroup case: value, type, computed
    verdict, and each trusted source's categorical vote + full report."""
    observables = []
    for art in case.observable_group.artifacts.select_related("url", "ip", "hash", "domain"):
        obj = art.observable()
        if obj is None:
            continue
        field = _FIELD[art.artifact_type]
        reports = (
            AnalyzerReport.objects.filter(**{field: obj})
            .select_related("analyzer")
            .order_by("-creation_date")
        )
        seen, sources, svs = set(), [], []
        for rep in reports:
            if rep.analyzer_id in seen:
                continue
            seen.add(rep.analyzer_id)
            sv = source_verdict_from_report(rep)
            svs.append(sv)
            # ponytail: report_full inlined per source — fine at current analyzer
            # counts; the downloadable report (Task 11) is the real full-detail surface.
            sources.append({
                "name": sv.name, "tier": sv.tier, "verdict": sv.verdict,
                "confidence": sv.confidence, "evidence": sv.evidence,
                "failed": sv.failed, "report_full": rep.report_full,
            })
        verdict = None
        if svs:
            v = score_observable(svs)
            verdict = {"band": v.band, "confidence": v.confidence, "rationale": v.rationale}
        observables.append({
            "value": getattr(obj, "address", None) or getattr(obj, "value", None),
            "type": art.artifact_type.lower(),
            "verdict": verdict,
            "sources": sources,
        })
    return observables
