"""Pure, DB-free case-scoring core. No Django models are queried or mutated
here — inputs are plain dataclasses, output is a CaseVerdict."""
from dataclasses import dataclass

from case_handler.models import Result

CONF_FLOOR = 50                 # below this a signal can't drive `worst`; a
                                # case below this is Inconclusive. Pinned in Task 6.
NEUTRAL = 5
MALICIOUS_SCORE_THRESHOLD = 8


@dataclass(frozen=True)
class Signal:
    source: str
    score: float          # 0–10, already weight-aggregated within the artifact
    confidence: float     # 0–100; doubles as the cross-artifact mean weight
    is_malicious: bool
    is_failure: bool


@dataclass(frozen=True)
class AiSignal:
    score: float          # 0–10
    confidence: float     # 0–100


@dataclass(frozen=True)
class CaseVerdict:
    final_score: float
    final_confidence: float
    result: str
    n_malicious: int
    n_scored: int


def band(score: float) -> str:
    if score <= 4:
        return Result.SAFE
    if score <= 7:
        return Result.SUSPICIOUS
    return Result.DANGEROUS


def score_case(signals, ai=None, deny_listed=False) -> CaseVerdict:
    scored = [s for s in signals if not s.is_failure]
    if not scored:
        return CaseVerdict(NEUTRAL, 0, Result.FAILURE, 0, 0)

    conf_sum = sum(s.confidence for s in scored) or 1
    worst = max((s.score for s in scored if s.confidence >= CONF_FLOOR), default=0)
    wmean = sum(s.score * s.confidence for s in scored) / conf_sum
    base_score = max(worst, wmean)
    base_conf = max(s.confidence for s in scored)

    if ai is not None and ai.confidence > base_conf:
        final_score, final_conf = ai.score, ai.confidence
    else:
        final_score, final_conf = base_score, base_conf

    # Round score once, before verdict checks — ensures final_score and result agree
    final_score = min(round(final_score), 10)

    n_malicious = sum(1 for s in scored if s.is_malicious)
    n_scored = len(scored)

    if deny_listed:
        result, final_score = Result.DANGEROUS, 10
    elif n_malicious >= max(1, n_scored // 3):
        result = Result.DANGEROUS
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
    )
