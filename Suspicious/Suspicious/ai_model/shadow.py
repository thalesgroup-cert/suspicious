"""Store the shadow model's answer for a case. Nothing here touches the live verdict."""
from __future__ import annotations

from ai_model.models import ModelVersion, ShadowResult


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
