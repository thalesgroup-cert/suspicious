from ai_model.presentation import present_assessment
from connectors.delivery import get_state


def ai_assessment_for(case, request):
    """The case's AI assessment payload, or None while the ai_model connector is off
    or there is no request to name the viewer."""
    if request is None or not get_state("ai_model").enabled:
        return None
    return present_assessment(case, request.user)
