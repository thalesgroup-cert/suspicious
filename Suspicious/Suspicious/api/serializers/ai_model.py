from rest_framework import serializers

from ai_model.models import ShadowReview


class ActionSerializer(serializers.Serializer):
    version_id = serializers.CharField(max_length=64, required=False)
    note = serializers.CharField(max_length=2000, required=False, allow_blank=True, default="")


class ExtendSerializer(ActionSerializer):
    days = serializers.IntegerField(min_value=1, max_value=365)


class ReviewSerializer(ActionSerializer):
    kind = serializers.ChoiceField(choices=ShadowReview.Kind.values)
    case_id = serializers.IntegerField(min_value=1)  # cast to int here, the service compares ints
    note = serializers.CharField(max_length=2000)  # non-empty, trimmed


def version_summary(v) -> dict:
    """Whitelist: no manifest, bundle prefix or URL ever leaves the registry."""
    recheck = v.recheck or {}
    return {
        "version_id": v.version_id, "status": v.status, "trigger": v.trigger,
        "created_at": v.created_at, "shadow_since": v.shadow_since, "shadow_min_days": v.shadow_min_days,
        "recheck": {k: recheck.get(k) for k in ("passed", "finished_at")} if recheck else None,
    }
