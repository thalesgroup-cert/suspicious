"""Per-observable report rows for an ObservableGroup case.

Shared by the investigation detail API (Task 9) and the downloadable report
(Task 11): value, type, computed categorical verdict, and every trusted
source's vote plus its analyzer report.
"""
from __future__ import annotations

from importlib import import_module

from score_process.scoring.observable_collect import (
    file_reports, mail_observable_reports, observable_reports,
)
from score_process.scoring.observable_engine import score_observable
from score_process.scoring.sources import source_verdict_from_report


def _parent_value(d):
    """Return the parent observable's value field (e.g., address, value)."""
    from cortex_job.cortex_utils.derived_observables import _MODEL_BY_TYPE

    spec = _MODEL_BY_TYPE.get(d.parent_type)
    if not spec:
        return None
    module, cls_name, field = spec
    obj = getattr(import_module(module), cls_name).objects.filter(pk=d.parent_id).first()
    return getattr(obj, field, None) if obj else None


def _source_rows(reports, *, full: bool) -> tuple[list[dict], list]:
    """Newest report per analyzer -> (source dicts, SourceVerdicts)."""
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
            "enrichment": rep.enrichment,
            "report": rep.report_full if full else rep.report_summary,
        })
    return sources, svs


def _verdict_dict(svs) -> dict | None:
    if not svs:
        return None
    v = score_observable(svs)
    return {"band": v.band, "confidence": v.confidence, "rationale": v.rationale}


def _screenshot_url(case, reports) -> str | None:
    shot = next((r.id for r in reports if getattr(r, "screenshot_key", "")), None)
    return f"/api/cases/{case.pk}/screenshot.png?report={shot}" if shot else None


def assemble_observables(case, *, full: bool = False) -> list[dict]:
    """Per-observable rows for an ObservableGroup case: value, type, computed
    verdict, and each trusted source's categorical vote + report.

    full=False (API detail) attaches report_summary; full=True (downloadable
    report) attaches report_full.
    """
    # ponytail: query derived_observables once before loop
    derived = {}       # (child_type, child_id) -> DerivedObservable
    escalation = {}    # (parent_type, parent_id) -> note
    for d in case.derived_observables.all():
        derived[(d.child_type, d.child_id)] = d
        if d.escalation_note:
            escalation[(d.parent_type, d.parent_id)] = d.escalation_note

    observables = []
    for art, obj, _field, reports in observable_reports(case):
        sources, svs = _source_rows(reports, full=full)
        verdict = _verdict_dict(svs)

        key = (art.artifact_type.lower(), obj.pk)
        d = derived.get(key)
        pv = _parent_value(d) if d else None
        observables.append({
            "value": getattr(obj, "address", None) or getattr(obj, "value", None),
            "type": art.artifact_type.lower(),
            "verdict": verdict,
            "sources": sources,
            # None when the parent row is gone: the frontend schema requires
            # derived_from.value to be a non-null string.
            "derived_from": ({"value": pv, "via_analyzer": d.via_analyzer}
                             if pv else None),
            "escalation_note": escalation.get(key, ""),
            "screenshot_url": _screenshot_url(case, reports),
        })
    return observables


def assemble_mail_observables(case, mail, *, full: bool = False) -> list[dict]:
    """One row per indicator embedded in a mail, same keys as assemble_observables."""
    out = []
    for _art, obj, field, reports in mail_observable_reports(mail):
        sources, svs = _source_rows(reports, full=full)
        out.append({
            "value": getattr(obj, "address", None) or getattr(obj, "value", None),
            "type": field, "verdict": _verdict_dict(svs), "sources": sources,
            "derived_from": None, "escalation_note": "",
            "screenshot_url": _screenshot_url(case, reports),
        })
    return out


def assemble_file_observable(case, file, *, full: bool = False) -> dict:
    from cortex_job.cortex_utils.cortex_and_job_management import ai_analyzer_name

    ai = ai_analyzer_name()  # the legacy AI report is not a file analyzer
    reports = [r for r in file_reports(file) if r.analyzer.name != ai]
    sources, svs = _source_rows(reports, full=full)
    return {
        "value": file.linked_hash.value, "type": "file",
        "verdict": _verdict_dict(svs), "sources": sources,
        "derived_from": None, "escalation_note": "",
        "screenshot_url": _screenshot_url(case, reports),
    }
