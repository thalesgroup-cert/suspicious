from django.db import models


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
