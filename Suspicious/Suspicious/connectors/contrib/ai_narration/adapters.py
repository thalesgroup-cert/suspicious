"""Turns a real Case's already-computed verdict into the dict shape
score_process.scoring.narration.{verdict_lock,prompt} expect. Never
re-derives the verdict -- reads only fields the scoring engines already
wrote."""
from __future__ import annotations

import json

from case_handler.models import Case

_KNOWN_BANDS = ("Safe", "Suspicious", "Dangerous", "Inconclusive")
_MAX_REPORTS = 20
_MAX_REPORT_FULL_CHARS = 4000


def _cap_report_full(report_full: dict) -> dict:
    serialized = json.dumps(report_full)
    if len(serialized) <= _MAX_REPORT_FULL_CHARS:
        return report_full
    return {
        "_truncated": True,
        "original_size_chars": len(serialized),
        "preview": serialized[:_MAX_REPORT_FULL_CHARS],
    }


def analyzer_reports_for_prompt(case: Case) -> list[dict]:
    """Deduped, capped analyzer_reports ready for build_prompt. Shared by
    the manual test_ai_narration command and the on_case_finalised hook."""
    from api.utils.analyzer_reports import reports_for_case
    from api.views.investigations import _dedup_analyzer_reports

    deduped = _dedup_analyzer_reports(reports_for_case(case))[:_MAX_REPORTS]
    return [
        {"analyzer": r.analyzer.name, "report_full": _cap_report_full(r.report_full)}
        for r in deduped
    ]


def case_to_verdict_dict(case: Case) -> dict:
    if case.results not in _KNOWN_BANDS:
        raise ValueError(
            f"case {case.pk} has band {case.results!r}, which the narration "
            f"lock does not model (only {_KNOWN_BANDS}) -- cannot safely narrate"
        )
    rule = "unknown"
    if case.verdict_explanation:
        rule = case.verdict_explanation.get("decisive_rule", "unknown")
    return {
        "band": case.results,
        "score": case.final_score,
        "confidence": case.final_confidence,
        "rule": rule,
    }
