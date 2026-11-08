import math
from rest_framework import serializers

from ai_model import retrain
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


def job_row(j) -> dict:
    """A RetrainJob without params, prefix or version ids; error is already filtered, capped again here."""
    return {"job_id": j.job_id, "state": j.state, "trigger": j.trigger, "rows": j.rows,
            "excluded_rows": j.excluded_rows, "started_at": j.started_at, "finished_at": j.finished_at,
            "error": j.error[:200]}


STR_CAP, MAX_DEPTH = 300, 4


def _plain(x, depth=0):
    """Depth-limited copy: numbers, booleans and short strings only (anything with a URL dropped)."""
    if isinstance(x, float):
        return x if math.isfinite(x) else None
    if isinstance(x, (bool, int)):
        return x
    if isinstance(x, str):
        return None if "http" in x.lower() else x[:STR_CAP]
    if depth >= MAX_DEPTH:
        return None
    if isinstance(x, dict):
        return {str(k)[:STR_CAP]: _plain(v, depth + 1) for k, v in x.items() if "http" not in str(k).lower()}
    if isinstance(x, (list, tuple)):
        return [_plain(v, depth + 1) for v in x[:50]]
    return None


def gate_view(manifest) -> dict | None:
    """Ruling G5: the GATE_KEYS whitelist of the stored gate, capped; None when there is no gate."""
    gate = (manifest or {}).get("gate")
    if not isinstance(gate, dict):
        return None
    return {k: _plain(gate.get(k)) for k in retrain.GATE_KEYS}


def _count(x):
    return x if isinstance(x, int) and not isinstance(x, bool) else None


def candidate_row(v) -> dict:
    m = v.manifest or {}
    return {"version_id": v.version_id, "status": v.status, "created_at": v.created_at, "trigger": v.trigger,
            "rows": _count(m.get("rows")), "excluded_rows": _count(m.get("excluded_rows")),
            "eligible": m.get("eligible") is True, "gate": gate_view(m)}
