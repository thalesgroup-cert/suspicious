"""Promote, roll back, extend and review shadow versions (Rulings F12, F13).

`can_promote` is the only place the promotion conditions live; `promote` re-evaluates them under
the row locks, so whatever a client sent, an unmet condition refuses the promotion. Pointer moves
go through registry.set_active; the server follows after commit (serversync, Ruling F2).
"""
import dataclasses
import logging
from datetime import datetime, timedelta

from django.db import transaction
from django.db.models import Max, Min, Q
from django.utils import timezone

from case_handler.models import CampaignMember

from . import registry, serversync
from .models import ModelVersion, ShadowCampaignEffect, ShadowResult, ShadowReview
from .registry import RegistryError
from .retrain import running_job

logger = logging.getLogger(__name__)
S = ModelVersion.Status
E = ShadowCampaignEffect.Effect

SHADOW_MIN_RESULTS = 500
DEFAULT_MIN_DAYS = 7  # ModelVersion.shadow_min_days default
WINDOW_DAYS = 15
RECHECK_MAX_AGE_DAYS = 7
MAX_MIN_DAYS = 365


class PromotionRefused(Exception):
    def __init__(self, codes):
        super().__init__("promotion refused: " + ", ".join(codes))
        self.codes = list(codes)


def critical_flips(version):
    """Live results whose would-be verdict flips Safe/Dangerous (Ruling F6)."""
    return list(ShadowResult.objects.filter(version=version, origin=ShadowResult.Origin.LIVE,
                                            flip=ShadowResult.Flip.CRITICAL).exclude(would_be_result=""))


def alert_delta(version):
    """Ruling F9, from the cases' current campaign membership."""
    effects = ShadowCampaignEffect.objects.filter(version=version)
    in_live = Q(case__campaign_membership__isnull=False)
    return {
        "candidate_only": sorted(effects.filter(effect__in=(E.WOULD_CREATE, E.WOULD_JOIN))
                                 .exclude(in_live).values_list("case_id", flat=True)),
        "active_only": sorted(effects.filter(in_live, effect__in=(E.NONE, E.NO_CHECK))
                              .values_list("case_id", flat=True)),
    }


def _items(version):
    delta = alert_delta(version)
    return ({("flip", r.case_id) for r in critical_flips(version)}
            | {("campaign", c) for c in delta["candidate_only"] + delta["active_only"]})


def latest_reviews(version):
    """{(kind, case_id): ShadowReview}, the latest review per item, current items only."""
    items = _items(version)
    latest = {}
    for r in ShadowReview.objects.filter(version=version).order_by("at", "pk"):
        if (r.kind, r.case_id) in items:
            latest[(r.kind, r.case_id)] = r
    return latest


def _active_profile():
    active = ModelVersion.objects.filter(status=S.ACTIVE).first()
    if active is not None:
        return active.campaign_profile
    from .campaign_profile import current_profile  # no active row: version 0's profile

    return dataclasses.asdict(current_profile())


def _recheck_code(version, now):
    recheck = version.recheck or {}
    if not recheck.get("finished_at"):
        return "recheck_missing"
    if recheck.get("passed") is not True:
        return "recheck_failed"
    try:
        finished = datetime.fromisoformat(recheck["finished_at"])
    except (TypeError, ValueError):
        return "recheck_missing"
    min_met = version.shadow_since + timedelta(days=version.shadow_min_days) if version.shadow_since else None
    if min_met is None or finished < min_met or now - finished > timedelta(days=RECHECK_MAX_AGE_DAYS):
        return "recheck_stale"
    return None


def can_promote(version) -> list:
    """Unmet conditions by stable code; empty when the version may be promoted. Reads the fields
    of the object given (promote passes the locked row)."""
    now = timezone.now()
    unmet = []
    if version.status != S.SHADOW:
        unmet.append("not_shadow")
    if not version.shadow_since or now < version.shadow_since + timedelta(days=version.shadow_min_days):
        unmet.append("too_young")
    if ShadowResult.objects.filter(version=version, origin=ShadowResult.Origin.LIVE).count() < SHADOW_MIN_RESULTS:
        unmet.append("too_few_results")
    reviewed = set(latest_reviews(version))
    if any(("flip", r.case_id) not in reviewed for r in critical_flips(version)):
        unmet.append("unreviewed_flips")
    delta = alert_delta(version)
    if any(("campaign", c) not in reviewed for c in delta["candidate_only"] + delta["active_only"]):
        unmet.append("unreviewed_campaigns")
    code = _recheck_code(version, now)
    if code:
        unmet.append(code)
    if version.campaign_profile != _active_profile():
        span = ShadowCampaignEffect.objects.filter(version=version).aggregate(a=Min("created_at"), b=Max("created_at"))
        if span["a"] is None or (span["b"].date() - span["a"].date()).days < WINDOW_DAYS:
            unmet.append("profile_window")
    # ponytail: plain read, not locked against a retrain starting concurrently; a job started
    # after the check trains on the ledger and cannot touch the pointer.
    if running_job() is not None:
        unmet.append("job_running")
    return unmet


def _sync_or_revert(revert):
    """After commit: a 4xx reload reverts the pointer and raises; a transient failure keeps it."""
    try:
        if not serversync.sync():
            logger.warning("ai_model server sync after a pointer move failed, the beat retries")
    except serversync.ReloadRefused:
        revert()
        raise


def promote(version, user, note=""):
    before = {}

    def run():
        with transaction.atomic():
            rows = list(ModelVersion.objects.select_for_update().order_by("pk").filter(
                Q(pk=version.pk) | Q(status__in=(S.ACTIVE, S.PREVIOUS))))
            target = next((r for r in rows if r.pk == version.pk), None)
            if target is None:
                raise RegistryError("unknown version")
            unmet = can_promote(target)
            if unmet:
                raise PromotionRefused(unmet)
            before.clear()
            before.update({r.status: r.pk for r in rows if r.pk != target.pk})
            registry.set_active(target, user, note)
            registry._event(target, "promote", user, note)

    registry._retry(run)
    _sync_or_revert(lambda: _revert_promote(version.pk, before, user))
    version.refresh_from_db()
    return version


def _revert_promote(pk, before, user):
    """Put back exactly what promote moved: the version to shadow, the old active back, the old
    previous (discarded by set_active) back to previous. Skipped if something moved meanwhile."""
    pks = [pk, *before.values()]

    def run():
        with transaction.atomic():
            rows = {r.pk: r for r in ModelVersion.objects.select_for_update().order_by("pk").filter(pk__in=pks)}
            target, old = rows.get(pk), rows.get(before.get(S.ACTIVE))
            if target is None or target.status != S.ACTIVE or (old and old.status != S.PREVIOUS):
                logger.warning("ai_model promote not reverted: the registry moved meanwhile")
                return
            target.status, target.active_slot, target.shadow_slot = S.SHADOW, None, 1
            target.save(update_fields=["status", "active_slot", "shadow_slot"])
            registry._event(target, "promote_reverted", user, "reload refused")
            if old:
                old.status, old.active_slot = S.ACTIVE, 1
                old.save(update_fields=["status", "active_slot"])
                registry._event(old, "promote_reverted", user, "reload refused")
            prev = rows.get(before.get(S.PREVIOUS))
            if prev and prev.status == S.DISCARDED:
                prev.status = S.PREVIOUS
                prev.save(update_fields=["status"])
                registry._event(prev, "promote_reverted", user, "reload refused")

    registry._retry(run)


def rollback(user, note=""):
    """The previous version becomes active again (registry.set_active swaps the two)."""
    previous = ModelVersion.objects.filter(status=S.PREVIOUS).first()
    if previous is None:
        raise RegistryError("no previous version to roll back to")
    old = ModelVersion.objects.filter(status=S.ACTIVE).first()

    with transaction.atomic():
        registry.set_active(previous, user, note)  # locks and re-checks the status
        registry._event(previous, "rollback", user, note)

    def revert():
        if old is None:
            return
        with transaction.atomic():
            registry.set_active(old, user, "reload refused")
            registry._event(old, "rollback_reverted", user, "reload refused")

    _sync_or_revert(revert)
    previous.refresh_from_db()
    return previous


def extend(version, days, user, note=""):
    """Raise the shadow's minimum period; it never goes down."""
    with transaction.atomic():
        locked = registry._lock(version)
        if locked.status != S.SHADOW:
            raise RegistryError(f"cannot extend a {locked.status} version")
        if not isinstance(days, int) or isinstance(days, bool) or not locked.shadow_min_days < days <= MAX_MIN_DAYS:
            raise RegistryError(f"days must be above {locked.shadow_min_days} and at most {MAX_MIN_DAYS}")
        locked.shadow_min_days = days
        locked.save(update_fields=["shadow_min_days"])
        registry._event(locked, "extend", user, f"{days} days" + (f": {note}" if note else ""))
    version.refresh_from_db()
    return version


def review(version, kind, case_id, user, note=""):
    """Append a review of one current flip or alert-delta item; refuses an item that does not exist."""
    if (kind, case_id) not in _items(version):
        raise RegistryError("no such review item for this version")
    return ShadowReview.objects.create(version=version, kind=kind, case_id=case_id, user=user, note=note)
