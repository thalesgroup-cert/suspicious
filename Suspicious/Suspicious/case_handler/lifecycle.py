from django.db import models
from django.utils import timezone


class LifecycleState(models.TextChoices):
    CREATED   = "CREATED",   "Created"
    ANALYZING = "ANALYZING", "Analyzing"
    SCORING   = "SCORING",   "Scoring"
    FINALIZED = "FINALIZED", "Finalized"
    CONTESTED = "CONTESTED", "Contested"


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
                               LifecycleState.FINALIZED},
    LifecycleState.ANALYZING: {LifecycleState.SCORING},
    LifecycleState.SCORING:   {LifecycleState.FINALIZED},
    # ANALYZING added on both terminal states for the redo-analysis feature:
    # an investigator can send a finished case back for a fresh analysis run.
    LifecycleState.FINALIZED: {LifecycleState.CONTESTED, LifecycleState.ANALYZING},
    LifecycleState.CONTESTED: {LifecycleState.FINALIZED, LifecycleState.ANALYZING},
}


def transition(case, to_state: str) -> None:
    current = case.lifecycle_state
    if to_state not in LEGAL_TRANSITIONS.get(current, set()):
        raise IllegalTransition(f"{current} -> {to_state} (case {case.id})")

    values = {"lifecycle_state": to_state, "status": STATUS_MAP[to_state]}
    finalized_at = case.finalized_at
    if to_state == LifecycleState.FINALIZED and finalized_at is None:
        finalized_at = timezone.now()
        values["finalized_at"] = finalized_at

    updated = type(case).objects.filter(id=case.id, lifecycle_state=current).update(**values)
    if not updated:
        raise IllegalTransition(
            f"{current} -> {to_state} (case {case.id}): lifecycle_state changed "
            "concurrently, aborting this transition"
        )

    case.lifecycle_state = to_state
    case.status = values["status"]
    if "finalized_at" in values:
        case.finalized_at = finalized_at
