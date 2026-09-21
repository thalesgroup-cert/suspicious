"""Turns a real Case's already-computed verdict into the dict shape
score_process.scoring.narration.{verdict_lock,prompt} expect. Never
re-derives the verdict -- reads only fields the scoring engines already
wrote."""
from __future__ import annotations

from case_handler.models import Case


def case_to_verdict_dict(case: Case) -> dict:
    rule = "unknown"
    if case.verdict_explanation:
        rule = case.verdict_explanation.get("decisive_rule", "unknown")
    return {
        "band": case.results,
        "score": case.final_score,
        "confidence": case.final_confidence,
        "rule": rule,
    }
