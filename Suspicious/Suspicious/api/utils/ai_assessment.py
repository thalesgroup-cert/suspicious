from api.permissions.submissions import has_elevated_view
from ai_model.presentation import present_assessment
from connectors.delivery import get_state
from connectors.registry import registry


def viewer_is_elevated(case, request) -> bool:
    """has_elevated_view, answered once per request and case (the serializers ask twice)."""
    cache = request.__dict__.setdefault("_elevated_view", {})
    if case.pk not in cache:
        cache[case.pk] = has_elevated_view(request.user, case)
    return cache[case.pk]


def ai_assessment_for(case, request):
    """The case's AI assessment payload, or None while the ai_model connector is off
    or there is no request to name the viewer."""
    if request is None or "ai_model" not in registry.names() or not get_state("ai_model").enabled:
        return None
    return present_assessment(case, request.user, elevated=viewer_is_elevated(case, request))
