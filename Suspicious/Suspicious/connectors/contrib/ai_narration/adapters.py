"""Turns a real Case's already-computed verdict into the dict shape
score_process.scoring.narration.{verdict_lock,prompt} expect. Never
re-derives the verdict -- reads only fields the scoring engines already
wrote."""
from __future__ import annotations

from case_handler.models import Case

_KNOWN_BANDS = ("Safe", "Suspicious", "Dangerous", "Inconclusive")


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
