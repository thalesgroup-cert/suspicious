"""When the daily check will next start a scheduled retrain (Plan G, ruling G4). Computed from the
same rules as retrain.maybe_start (they share retrain.interval_days and retrain.newest_version),
never stored."""
from datetime import timedelta

from django.utils import timezone

from ai_model import ledger, retrain
from ai_model.models import ModelVersion, RetrainJob


_UNSET = object()


def config() -> dict:
    return retrain._connector(check_enabled=False).config


def backoff_until(now=None):
    """End of the backoff after the latest failed or refused scheduled job; None when none is recent."""
    now = now or timezone.now()
    last = (RetrainJob.objects.filter(trigger=ModelVersion.Trigger.SCHEDULE, state=RetrainJob.State.FAILED,
                                      started_at__gte=now - retrain.BACKOFF)
            .order_by("-started_at").first())
    return last.started_at + retrain.BACKOFF if last else None


def next_run(now=None, *, cfg=None, running=_UNSET, backoff=_UNSET):
    """None when the connector is disabled, scheduling is off or a job runs; else the newest version's
    age limit, pushed to the end of the backoff. The beat check runs once a day, so the date is
    approximate. cfg, running (a job or None) and backoff may be passed to save repeat reads."""
    now = now or timezone.now()
    cfg = config() if cfg is None else cfg
    running = retrain.running_job() if running is _UNSET else running
    if not ledger.enabled() or cfg.get("retrain_enabled") is not True or running:
        return None
    newest = retrain.newest_version()
    due = newest.created_at + timedelta(days=retrain.interval_days(cfg)) if newest else now
    backoff = backoff_until(now) if backoff is _UNSET else backoff
    return max(due, backoff or due)
