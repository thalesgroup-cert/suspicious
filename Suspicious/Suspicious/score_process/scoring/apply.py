"""Persist a CaseVerdict onto the Case and fire finalisation side-effects.
The only place Case scoring fields are written by the scoring path."""
import logging

from score_process.scoring.update_handler import (
    save_case_results, update_kpi_and_user_stats,
)

logger = logging.getLogger(__name__)

_DERIVED_SCORE = {"Safe": 2, "Suspicious": 6, "Dangerous": 9, "Inconclusive": 5}
# Map the categorical band onto the legacy IOC-level vocabulary
# (safe/info/suspicious/malicious/critical) that admin filters + cross-case
# reuse read — the ObservableGroup rows are globally shared.
_BAND_TO_IOC_LEVEL = {
    "Safe": "safe", "Inconclusive": "info",
    "Suspicious": "suspicious", "Dangerous": "malicious",
}
# Stronger markers set by other paths (deny list / allow list) — never
# downgraded by an IOC-road re-score.
_STICKY_IOC_LEVELS = {"critical", "SAFE-ALLOW_LISTED"}
_BAND_RANK = {"Safe": 0, "Inconclusive": 0, "Suspicious": 1, "Dangerous": 2}


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


def _deny_listed_value(art_type, obj, deny):
    """The deny list is domain-based; check a DOMAIN observable's value and a
    URL observable's host against it. Returns the matched host or None."""
    from urllib.parse import urlparse

    from score_process.scoring.case_score_calculation import _is_address_deny_listed

    if art_type == "DOMAIN":
        host = getattr(obj, "value", "") or ""
    elif art_type == "URL":
        host = urlparse(getattr(obj, "address", "") or "").hostname or ""
    else:
        return None
    if host and _is_address_deny_listed(host, deny, logger):
        return host
    return None


def finalise_ioc_group(case) -> None:
    """IOC-road finalisation via the categorical engine. Never calls score_case."""
    from case_handler.models import Result
    from score_process.scoring.case_score_calculation import get_deny_listed_domains_set
    from score_process.scoring.observable_collect import collect_observable_sources
    from score_process.scoring.observable_engine import (
        ObservableVerdict, score_group, score_observable,
    )

    deny = get_deny_listed_domains_set()
    per_obs = collect_observable_sources(case)
    obs_verdicts = []
    idx_by_key = {}
    for (_art_type, _pk, obj), sources in per_obs.items():
        v = score_observable(sources)
        matched = _deny_listed_value(_art_type, obj, deny)
        if matched:
            v = ObservableVerdict(
                "Dangerous", 100, None, v.counts,
                list(v.rationale) + [f"Indicator is on the deny list ({matched})."],
            )
        idx_by_key[(_art_type.lower(), obj.pk)] = len(obs_verdicts)
        obs_verdicts.append(v)
        if obj.ioc_level not in _STICKY_IOC_LEVELS:
            obj.ioc_level = _BAND_TO_IOC_LEVEL.get(v.band, "info")
        obj.ioc_score = _DERIVED_SCORE.get(v.band, 5)
        obj.ioc_confidence = v.confidence
        obj.save(update_fields=["ioc_level", "ioc_score", "ioc_confidence"])

    # Derived-observable escalation: a child (extracted) observable that scored
    # worse than its parent raises the parent's verdict. _parent_band re-reads
    # ioc_level, which the loop above has just persisted.
    from cortex_job.cortex_utils.derived_observables import score_derived_observables

    obj_by_key = {(_art.lower(), o.pk): o for (_art, _p, o) in per_obs}
    for (ptype, pid), (eband, note) in score_derived_observables(case).items():
        i = idx_by_key.get((ptype, pid))
        if i is None:
            continue
        v = obs_verdicts[i]
        if _BAND_RANK.get(eband, 0) <= _BAND_RANK.get(v.band, 0):
            continue
        obs_verdicts[i] = ObservableVerdict(
            eband, v.confidence, None, v.counts, list(v.rationale) + [note])
        obj = obj_by_key[(ptype, pid)]
        if obj.ioc_level not in _STICKY_IOC_LEVELS:
            obj.ioc_level = _BAND_TO_IOC_LEVEL.get(eband, "info")
        obj.ioc_score = _DERIVED_SCORE.get(eband, 5)
        obj.save(update_fields=["ioc_level", "ioc_score"])

    g = score_group(obs_verdicts) if obs_verdicts else None
    band = g.band if g else "Inconclusive"
    case.results = getattr(Result, band.upper(), Result.INCONCLUSIVE)
    case.score = case.final_score = _DERIVED_SCORE.get(band, 5)
    case.confidence = case.final_confidence = g.confidence if g else 0
    rationale = list(g.rationale) if g else []
    for v in obs_verdicts:
        rationale.extend(v.rationale)
    case.verdict_rationale = rationale
    # analyzer-report count (matches the mail road's verdict.n_scored), not the
    # observable count — feeds _describe()'s "reused" branch + the admin/UI field.
    case.analysis_done = sum(len(s) for s in per_obs.values())
    case.save(update_fields=[
        "results", "score", "final_score", "confidence", "final_confidence",
        "verdict_rationale", "analysis_done",
    ])
    update_kpi_and_user_stats(case)
