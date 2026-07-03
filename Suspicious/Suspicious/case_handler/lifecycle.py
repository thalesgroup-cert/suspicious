from django.db import models
from django.utils import timezone


class LifecycleState(models.TextChoices):
    CREATED   = "CREATED",   "Created"
    ANALYZING = "ANALYZING", "Analyzing"
    SCORING   = "SCORING",   "Scoring"
    FINALIZED = "FINALIZED", "Finalized"
    CONTESTED = "CONTESTED", "Contested"


# lifecycle_state -> analyst-facing Case.status display value
STATUS_MAP = {
    LifecycleState.CREATED:   "On Going",
    LifecycleState.ANALYZING: "On Going",
    LifecycleState.SCORING:   "On Going",
    LifecycleState.FINALIZED: "Done",
    LifecycleState.CONTESTED: "Challenged",
}


class IllegalTransition(Exception):
    """Raised when a case is moved between two states with no legal edge."""


LEGAL_TRANSITIONS = {
    LifecycleState.CREATED:   {LifecycleState.ANALYZING, LifecycleState.SCORING,
                               LifecycleState.FINALIZED},   # FINALIZED = allow-listed shortcut
    LifecycleState.ANALYZING: {LifecycleState.SCORING},
    LifecycleState.SCORING:   {LifecycleState.FINALIZED},
    LifecycleState.FINALIZED: {LifecycleState.CONTESTED},
    LifecycleState.CONTESTED: {LifecycleState.FINALIZED},
}


def transition(case, to_state: str) -> None:
    current = case.lifecycle_state
    if to_state not in LEGAL_TRANSITIONS.get(current, set()):
        raise IllegalTransition(f"{current} -> {to_state} (case {case.id})")
    case.lifecycle_state = to_state
    case.status = STATUS_MAP[to_state]
    fields = ["lifecycle_state", "status"]
    if to_state == LifecycleState.FINALIZED and case.finalized_at is None:
        case.finalized_at = timezone.now()
        fields.append("finalized_at")
    case.save(update_fields=fields)
