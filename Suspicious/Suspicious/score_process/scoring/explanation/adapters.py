"""Turn a scoring-engine result + the case's analyzer reports into one
``VerdictExplanation``. Read-only: no ORM writes, no verdict logic — just
translation of what the engine already decided into structured text.

Task 7 calls these at finalisation; Task 8 uses them in a backfill.
"""
from __future__ import annotations

from score_process.scoring.explanation.compose import compose
from score_process.scoring.explanation.types import SourceLine, VerdictExplanation
from score_process.scoring.sources import source_verdict_from_report

_FLAGGED = ("malicious", "suspicious")

# rule key -> predicate over a SourceVerdict: did this source feed the decisive rule?
_COUNTED_PREDICATES = {
    "tier1-authoritative-malicious": lambda sv: sv.tier == 1 and sv.verdict == "malicious",
    "tier2-consensus-malicious": lambda sv: sv.tier == 2 and sv.verdict == "malicious",
    "weighted-malicious-share": lambda sv: sv.verdict == "malicious",
    "tier1-authoritative-clean": lambda sv: sv.tier == 1 and sv.verdict == "clean",
    "trusted-flag-not-decisive": lambda sv: sv.tier in (1, 2) and sv.verdict in _FLAGGED,
    "contextual-only-flag": lambda sv: sv.tier == 3 and sv.verdict in _FLAGGED,
    "group-worst-of": lambda sv: sv.verdict in _FLAGGED,
    "weighted-consensus": lambda sv: sv.verdict in _FLAGGED,
    "single-strong-signal": lambda sv: sv.verdict in _FLAGGED and (sv.confidence or 0) >= 50,
    "embedded-ioc-escalation": lambda sv: sv.verdict in _FLAGGED,
    "ai-classifier-decisive": lambda sv: "ai_mail" in sv.name.lower()
    or "aimailanalyzer" in sv.name.lower().replace("_", ""),
}

_BANDS = {"Safe", "Suspicious", "Dangerous", "Inconclusive"}


def _counted(rule, sv) -> bool:
    pred = _COUNTED_PREDICATES.get(rule)
    return bool(pred(sv)) if pred else False


def _missing_phrase(reason) -> str:
    if reason == "thin_coverage":
        return "no authoritative source returned a verdict"
    if not reason:
        return "coverage is thin"
    return str(reason)


def _norm_band(value) -> str:
    # value may be a plain str or a Result (TextChoices, a str subclass) — both
    # compare/hash as their string value, so set membership handles either.
    value = getattr(value, "value", value)
    return value if value in _BANDS else "Inconclusive"


def _case_data_type(case) -> str:
    """Best-effort "url" / "domain" / "mail" / "indicator" from the case."""
    try:
        fom = getattr(case, "fileOrMail", None)
        if fom is not None:
            if getattr(fom, "mail_id", None):
                return "mail"
            if getattr(fom, "file_id", None):
                return "file"
        grp = getattr(case, "observable_group", None)
        if grp is not None:
            types = {a.artifact_type for a in grp.artifacts.all()}
            if len(types) == 1:
                return next(iter(types)).lower()
        nfi = getattr(case, "nonFileIocs", None)
        if nfi is not None:
            for attr in ("url", "ip", "hash"):
                if getattr(nfi, f"{attr}_id", None):
                    return attr
    except Exception:  # ponytail: data_type is cosmetic; "indicator" is a fine fallback
        pass
    return "indicator"


def _source_lines(rule, reports) -> list[SourceLine]:
    lines = []
    for report in reports:
        sv = source_verdict_from_report(report)
        lines.append(SourceLine(
            name=report.analyzer.name,
            tier=sv.tier,
            verdict="failed" if sv.failed else sv.verdict,
            counted=_counted(rule, sv),
            note=(sv.evidence or "")[:60],
        ))
    lines.sort(key=lambda s: (not s.counted, s.tier, s.name))
    return lines


def _build(rule, band, confidence, source_lines, data_type, missing,
           n_counted=None, n_total=None) -> VerdictExplanation:
    counted = sum(1 for s in source_lines if s.counted)
    facts = dict(
        source=next((s.name for s in source_lines if s.counted), "a source"),
        n_context=len(source_lines) - counted,
        n_counted=counted if n_counted is None else n_counted,
        n_total=len(source_lines) if n_total is None else n_total,
        data_type=data_type,
        missing=missing,
    )
    analyst, reporter, reading = compose(rule, band, confidence, source_lines, **facts)
    return VerdictExplanation(band, int(confidence), rule, analyst, reporter, reading, tuple(source_lines))


def explain_observable_group(case, group_verdict, per_observable, reports) -> VerdictExplanation:
    """IOC road: one group case (or a single-observable case) -> explanation.

    ``group_verdict``: GroupVerdict | None (None if the case had no observables)
    ``per_observable``: list[ObservableVerdict], post-escalation
    ``reports``: iterable[AnalyzerReport] for the case
    """
    per_observable = list(per_observable or [])
    n_counted = n_total = None

    # finalise_ioc_group always builds a group verdict (score_group runs whenever
    # there is >=1 observable), so `group_verdict is not None` can't be the test
    # for "is this a real group case". Branch on the observable count instead.
    if len(per_observable) == 1 or (per_observable and group_verdict is None):
        o = per_observable[0]
        rule = o.rule or "unknown"
        band = o.band
        confidence = o.confidence
        reason = o.inconclusive_reason
    elif group_verdict is not None:
        rule = group_verdict.rule or "group-worst-of"
        band = group_verdict.band
        confidence = group_verdict.confidence
        reason = getattr(group_verdict, "inconclusive_reason", None)
        if len(per_observable) > 1:
            # "{n_counted} of {n_total} submitted indicator(s)" counts observables
            n_counted = group_verdict.counts.get(group_verdict.band, 0)
            n_total = len(per_observable)
    else:
        rule = "thin-coverage"
        band = "Inconclusive"
        confidence = 0
        reason = None

    source_lines = _source_lines(rule, reports)
    return _build(rule, band, confidence, source_lines,
                  _case_data_type(case), _missing_phrase(reason),
                  n_counted=n_counted, n_total=n_total)


def explain_mail_case(case, verdict, analyzer_reports, embedded_verdicts) -> VerdictExplanation:
    """Mail road: a CaseVerdict + the case's analyzer reports -> explanation.

    ``embedded_verdicts`` (list[ObservableVerdict], may be []) is accepted for
    Task 7's call signature; the decisive rule already encodes any embedded-IOC
    escalation, so the reports carry all the source detail we render.
    """
    rule = verdict.rule or "unknown"
    band = _norm_band(str(verdict.result))
    confidence = int(verdict.final_confidence)
    missing = _missing_phrase(getattr(verdict, "inconclusive_reason", "") or "")

    source_lines = _source_lines(rule, analyzer_reports)
    return _build(rule, band, confidence, source_lines, _case_data_type(case), missing)
