"""Per-observable report rows for an ObservableGroup case.

Shared by the investigation detail API (Task 9) and the downloadable report
(Task 11): value, type, computed categorical verdict, and every trusted
source's vote plus its analyzer report.
"""
from __future__ import annotations

from score_process.scoring.observable_collect import observable_reports
from score_process.scoring.observable_engine import score_observable
from score_process.scoring.sources import source_verdict_from_report


def assemble_observables(case, *, full: bool = False) -> list[dict]:
    """Per-observable rows for an ObservableGroup case: value, type, computed
    verdict, and each trusted source's categorical vote + report.

    full=False (API detail) attaches report_summary; full=True (downloadable
    report) attaches report_full.
    """
    observables = []
    for art, obj, _field, reports in observable_reports(case):
        seen, sources, svs = set(), [], []
        for rep in reports:
            if rep.analyzer_id in seen:
                continue
            seen.add(rep.analyzer_id)
            sv = source_verdict_from_report(rep)
            svs.append(sv)
            sources.append({
                "name": sv.name, "tier": sv.tier, "verdict": sv.verdict,
                "confidence": sv.confidence, "evidence": sv.evidence,
                "failed": sv.failed,
                "report": rep.report_full if full else rep.report_summary,
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
