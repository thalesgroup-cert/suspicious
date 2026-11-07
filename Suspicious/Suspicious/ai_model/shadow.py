"""Store the shadow model's answer for a case. Nothing here touches the live verdict."""
from __future__ import annotations

from ai_model.models import AiAssessment, ModelVersion, ShadowResult
from case_handler.models import Result
from score_process.scoring.engine import AiSignal, score_case


def store_shadow_result(case, payload: dict):
    """Upsert the (case, version) row from a server shadow answer; None when its version is not
    the registry's current shadow (a promote or discard raced it). Maps like ProviderResult."""
    version = ModelVersion.objects.filter(
        status=ModelVersion.Status.SHADOW, version_id=payload["version"]).first()
    if version is None:
        return None
    sub_class = str(payload["sub_class"])
    row, _ = ShadowResult.objects.update_or_create(case=case, version=version, defaults={
        "origin": ShadowResult.Origin.LIVE,
        "result": payload["class"],
        "sub_class": sub_class[:ShadowResult._meta.get_field("sub_class").max_length],
        "score": round(float(payload["score"])),
        "confidence": min(round(float(payload["confidence"]) * 100), 100),
        "probabilities": payload["probabilities"],
        "tier": payload.get("tier") or "",
    })
    return row


def flip_of(live: str, would_be: str) -> str:
    """Ruling F6: only Safe <-> Dangerous is critical; Inconclusive and Suspicious never are."""
    if live == would_be:
        return ShadowResult.Flip.NONE
    if {live, would_be} == {Result.SAFE, Result.DANGEROUS}:
        return ShadowResult.Flip.CRITICAL
    return ShadowResult.Flip.CHANGED


def record_would_be(case, signals, deny_listed, deny_reason, evidence, live_verdict):
    """Ruling F5: rescore the live pass's inputs with the shadow's AI answer and store the verdict
    on the case's live ShadowResult. Pure apart from that one row: the signals, the deny-list
    flag and the embedded evidence come from the live pass, so nothing is collected twice."""
    from score_process.scoring.collect import collect_votes
    from score_process.scoring.cortex_analyzers.reports import CortexAnalyzerReports

    row = ShadowResult.objects.filter(
        case=case, version__status=ModelVersion.Status.SHADOW, origin=ShadowResult.Origin.LIVE,
    ).first()
    if row is None or row.error:
        return None
    missing = row.result == AiAssessment.Result.INCONCLUSIVE
    ai = None
    if row.confidence and not missing:   # as collect_signals builds the live AI signal
        ai = AiSignal(score=row.score, confidence=min(round(row.confidence), 100))
    try:
        votes = collect_votes(case, ai)
    except Exception:
        votes = ()   # as get_report does for the live pass
    would = CortexAnalyzerReports._escalate(
        score_case(signals, ai, deny_listed, missing, deny_reason, votes=votes), evidence)
    row.live_result, row.would_be_result = live_verdict.result, would.result
    row.would_be_score, row.would_be_confidence = would.final_score, would.final_confidence
    row.would_be_rule = would.rule[:ShadowResult._meta.get_field("would_be_rule").max_length]
    row.flip = flip_of(live_verdict.result, would.result)
    row.save(update_fields=["live_result", "would_be_result", "would_be_score",
                            "would_be_confidence", "would_be_rule", "flip"])
    return row
