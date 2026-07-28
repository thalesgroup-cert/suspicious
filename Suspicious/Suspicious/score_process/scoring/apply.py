"""Persist a CaseVerdict onto the Case and fire finalisation side-effects.
The only place Case scoring fields are written by the scoring path."""
from score_process.scoring.update_handler import (
    save_case_results, update_kpi_and_user_stats,
)


def apply_verdict(case, verdict) -> None:
    case.final_score = verdict.final_score
    case.final_confidence = verdict.final_confidence
    case.score = verdict.final_score
    case.confidence = verdict.final_confidence
    case.results = verdict.result
    case.analysis_done = verdict.n_scored
    case.is_denylisted = verdict.is_denylisted
    case.list_reason = verdict.list_reason
    case.save(update_fields=[
        "final_score", "final_confidence", "score", "confidence",
        "results", "analysis_done", "is_denylisted", "list_reason",
    ])

    mail = getattr(case.fileOrMail, "mail", None) if case.fileOrMail else None
    save_case_results(case, mail)
    update_kpi_and_user_stats(case)
