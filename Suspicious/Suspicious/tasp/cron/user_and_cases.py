import logging
from django.contrib.auth.models import User
from case_handler.lifecycle import LifecycleState
from case_handler.models import Case
from profiles.profiles_utils.ldap import Ldap
from tasp.tasks import reconcile_case

logger = logging.getLogger("tasp.cron.users_cases")
log_cases = logging.getLogger("tasp.cron.update_ongoing_case_jobs")

CRON_BATCH_SIZE = 200


def sync_user_profiles() -> None:
    """Synchronise user profiles via LDAP.

    Restricted to active users and streamed in chunks so a large user
    table is not pulled into memory at every cron tick, and LDAP is
    not pinged for disabled accounts.
    """
    for user in User.objects.filter(is_active=True).iterator(chunk_size=100):
        try:
            Ldap.create_user(user)
        except Exception:
            logger.exception("Failed to sync user %s", user.pk)


def update_ongoing_cases() -> None:
    """Fallback sweep: enqueue `reconcile_case` for every non-terminal case.

    Bounded scan: at most CRON_BATCH_SIZE oldest cases per tick. Covers
    cases whose webhook delivery was missed/delayed *and* jobless cases
    (zero CaseAnalyzerJob rows) that no per-job trigger would ever revisit.
    No lock is taken here — `reconcile_case` owns the per-case
    `case_update_lock:<id>` lock, so a case already being processed by the
    webhook task is simply skipped there and re-picked up next tick.
    """
    _TERMINAL = (LifecycleState.FINALIZED, LifecycleState.CONTESTED)
    case_ids = list(
        Case.objects
        .exclude(lifecycle_state__in=_TERMINAL)
        .order_by("creation_date")
        .values_list("id", flat=True)[:CRON_BATCH_SIZE]
    )
    if not case_ids:
        log_cases.info("No ongoing cases found.")
        return
    for cid in case_ids:
        reconcile_case.delay(cid)
