"""Persist a CaseVerdict onto the Case and fire finalisation side-effects.
The only place Case scoring fields are written by the scoring path."""
from score_process.scoring.update_handler import (
    save_case_results, update_kpi_and_user_stats,
)

_DERIVED_SCORE = {"Safe": 2, "Suspicious": 6, "Dangerous": 9, "Inconclusive": 5}


def apply_verdict(case, verdict) -> None:
    case.final_score = verdict.final_score
    case.final_confidence = verdict.final_confidence
    case.score = verdict.final_score
    case.confidence = verdict.final_confidence
    case.results = verdict.result
    case.analysis_done = verdict.n_scored
    case.is_denylisted = verdict.is_denylisted
    case.list_reason = verdict.list_reason
    case.inconclusive_reason = getattr(verdict, "inconclusive_reason", "") or ""
    case.verdict_rationale = list(getattr(verdict, "rationale", ()) or [])
    case.save(update_fields=[
        "final_score", "final_confidence", "score", "confidence",
        "results", "analysis_done", "is_denylisted", "list_reason",
        "inconclusive_reason", "verdict_rationale",
    ])

    mail = getattr(case.fileOrMail, "mail", None) if case.fileOrMail else None
    save_case_results(case, mail)
    update_kpi_and_user_stats(case)


def finalise_ioc_group(case) -> None:
    """IOC-road finalisation via the categorical engine. Never calls score_case."""
    from case_handler.models import Result
    from score_process.scoring.observable_collect import collect_observable_sources
    from score_process.scoring.observable_engine import score_group, score_observable

    per_obs = collect_observable_sources(case)
    obs_verdicts = []
    for (_art_type, _pk, obj), sources in per_obs.items():
        v = score_observable(sources)
        obs_verdicts.append(v)
        obj.ioc_level = v.band.lower()
        obj.ioc_score = _DERIVED_SCORE.get(v.band, 5)
        obj.ioc_confidence = v.confidence
        obj.save(update_fields=["ioc_level", "ioc_score", "ioc_confidence"])

    g = score_group(obs_verdicts) if obs_verdicts else None
    band = g.band if g else "Inconclusive"
    case.results = getattr(Result, band.upper(), Result.INCONCLUSIVE)
    case.score = case.final_score = _DERIVED_SCORE.get(band, 5)
    case.confidence = case.final_confidence = g.confidence if g else 0
    rationale = list(g.rationale) if g else []
    for v in obs_verdicts:
        rationale.extend(v.rationale)
    case.verdict_rationale = rationale
    case.analysis_done = len(obs_verdicts)
    case.save(update_fields=[
        "results", "score", "final_score", "confidence", "final_confidence",
        "verdict_rationale", "analysis_done",
    ])
    update_kpi_and_user_stats(case)
