"""Pure, DB-free case-scoring core. No Django models are queried or mutated
here — inputs are plain dataclasses, output is a CaseVerdict."""
from dataclasses import dataclass, replace

from case_handler.models import Result

CONF_FLOOR = 50
NEUTRAL = 5
MALICIOUS_SCORE_THRESHOLD = 8


@dataclass(frozen=True)
class Signal:
    source: str
    score: float
    confidence: float
    is_malicious: bool
    is_failure: bool


@dataclass(frozen=True)
class AiSignal:
    score: float
    confidence: float


@dataclass(frozen=True)
class CaseVerdict:
    final_score: float
    final_confidence: float
    result: str
    n_malicious: int
    n_scored: int
    is_denylisted: bool = False
    list_reason: str = ""
    inconclusive_reason: str = ""
    n_failed: int = 0
    rationale: tuple = ()
    rule: str = ""


_BAND_RANK = {Result.SAFE: 0, Result.INCONCLUSIVE: 0, Result.SUSPICIOUS: 1, Result.DANGEROUS: 2}
_OBS_TO_RESULT = {"Safe": Result.SAFE, "Suspicious": Result.SUSPICIOUS, "Dangerous": Result.DANGEROUS}


def mail_band_escalation(verdict, embedded, note: str = ""):
    """Raise (never lower) a mail case's band to the worst embedded-IOC band.
    final_score is untouched — the AI/YARA/sandbox score still owns the number.

    When `note` is given it is recorded on the rationale even if the band
    already sat at/above the embedded band: on the mail road the embedded
    child's own analyzer reports usually move the case verdict on their own,
    but the analyst still needs the line saying *which* extraction did it."""
    if not embedded:
        return verdict
    if verdict.result not in _BAND_RANK:
        return verdict
    worst = max(
        (_OBS_TO_RESULT[o.band] for o in embedded if o.band in _OBS_TO_RESULT),
        key=lambda r: _BAND_RANK[r], default=None,
    )
    if worst is None:
        return verdict
    raising = _BAND_RANK[worst] > _BAND_RANK.get(verdict.result, 0)
    if not raising and not note:
        return verdict
    line = note or f"Band raised to {worst} by an embedded indicator."
    new_conf = verdict.final_confidence
    if raising:
        worst_conf = max((getattr(o, "confidence", 0) for o in embedded
                          if _OBS_TO_RESULT.get(o.band) == worst), default=0)
        new_conf = max(verdict.final_confidence, min(round(worst_conf), 100))
    return replace(
        verdict,
        result=worst if raising else verdict.result,
        final_confidence=new_conf,
        rationale=tuple(verdict.rationale) + (line,),
        **({"rule": "embedded-ioc-escalation"} if raising else {}),
    )


def band(score: float) -> str:
    if score <= 4:
        return Result.SAFE
    if score <= 7:
        return Result.SUSPICIOUS
    return Result.DANGEROUS


def _classify_rule(*, ai, base_conf, ai_missing, final_score, final_conf,
                   n_malicious, n_scored, result, worst, wmean) -> str:
    # Mirror score_case's band order: the malicious-count test decides Dangerous
    # before any incomplete-analysis branch, so it must be checked first here too.
    if n_malicious >= max(1, n_scored // 3):
        return "weighted-consensus"
    if ai is not None and ai.confidence > base_conf:
        return "ai-classifier-decisive"
    if ai_missing:
        return "analysis-incomplete"
    if final_score == NEUTRAL or final_conf < CONF_FLOOR:
        return "analysis-incomplete"
    if result == Result.SAFE and n_malicious == 0:
        return "no-signal"
    if worst > wmean:
        return "single-strong-signal"
    return "weighted-consensus"


def score_case(signals, ai=None, deny_listed=False, ai_missing=False, deny_reason="") -> CaseVerdict:
    scored = [s for s in signals if not s.is_failure]
    n_malicious = sum(1 for s in scored if s.is_malicious)
    n_scored = len(scored)

    if deny_listed:
        return CaseVerdict(10, 100, Result.DANGEROUS, n_malicious, n_scored, is_denylisted=True,
                           list_reason=deny_reason, rule="deny-listed")

    if not scored:
        return CaseVerdict(NEUTRAL, 0, Result.FAILURE, 0, 0, rule="analysis-incomplete")

    conf_sum = sum(s.confidence for s in scored) or 1
    worst = max((s.score for s in scored if s.confidence >= CONF_FLOOR), default=0)
    wmean = sum(s.score * s.confidence for s in scored) / conf_sum
    base_score = max(worst, wmean)
    base_conf = max(s.confidence for s in scored)

    if ai is not None and ai.confidence > base_conf:
        final_score, final_conf = ai.score, ai.confidence
    else:
        final_score, final_conf = base_score, base_conf

    final_score = min(round(final_score), 10)

    if n_malicious >= max(1, n_scored // 3):
        result = Result.DANGEROUS
    elif ai_missing:
        result = Result.INCONCLUSIVE
    elif final_score == NEUTRAL or final_conf < CONF_FLOOR:
        result = Result.INCONCLUSIVE
    else:
        result = band(final_score)

    return CaseVerdict(
        final_score=final_score,
        final_confidence=min(round(final_conf), 100),
        result=result,
        n_malicious=n_malicious,
        n_scored=n_scored,
        rule=_classify_rule(
            ai=ai, base_conf=base_conf, ai_missing=ai_missing,
            final_score=final_score, final_conf=final_conf,
            n_malicious=n_malicious, n_scored=n_scored,
            result=result, worst=worst, wmean=wmean,
        ),
    )
