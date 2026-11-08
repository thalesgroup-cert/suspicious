"""When the daily check will next start a scheduled retrain (Plan G, ruling G4). Computed from the
same rules as retrain.maybe_start, never stored."""
from datetime import timedelta

from django.utils import timezone

from ai_model import retrain
from ai_model.models import ModelVersion, RetrainJob


def config() -> dict:
    return retrain._connector(check_enabled=False).config


def interval_days(cfg=None) -> int:
    try:
        return max(int((cfg if cfg is not None else config()).get("retrain_interval_days", 30)), 0)
    except (TypeError, ValueError):
        return 30


def backoff_until(now=None):
    """End of the backoff after the latest failed or refused scheduled job; None when none is recent."""
    now = now or timezone.now()
    last = (RetrainJob.objects.filter(trigger=ModelVersion.Trigger.SCHEDULE, state=RetrainJob.State.FAILED,
                                      started_at__gte=now - retrain.BACKOFF)
            .order_by("-started_at").first())
    return last.started_at + retrain.BACKOFF if last else None


def next_run(now=None):
    """None when scheduling is off or a job runs; else the newest version's age limit, pushed to the
    end of the backoff. The beat check runs once a day, so the date is approximate."""
    now = now or timezone.now()
    cfg = config()
    if cfg.get("retrain_enabled") is not True or retrain.running_job() is not None:
        return None
    S = ModelVersion.Status
    newest = (ModelVersion.objects.filter(status__in=(S.CANDIDATE, S.SHADOW, S.ACTIVE, S.PREVIOUS))
              .order_by("-created_at").first())
    due = newest.created_at + timedelta(days=interval_days(cfg)) if newest else now
    return max(due, backoff_until(now) or due)
