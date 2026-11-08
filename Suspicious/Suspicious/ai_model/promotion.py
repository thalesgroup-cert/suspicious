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


def snapshot(version):
    """The review items read once: {"critical": [ShadowResult], "delta": alert_delta}. Callers that
    need several of can_promote, latest_reviews and the lists pass one snapshot around."""
    return {"critical": critical_flips(version), "delta": alert_delta(version)}


def _items(version, snap=None):
    snap = snap or snapshot(version)
    delta = snap["delta"]
    return ({("flip", r.case_id) for r in snap["critical"]}
            | {("campaign", c) for c in delta["candidate_only"] + delta["active_only"]})


def latest_reviews(version, snap=None):
    """{(kind, case_id): ShadowReview}, the latest review per item, current items only."""
    items = _items(version, snap)
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
    if finished.tzinfo is None:  # record_recheck always stores UTC with an offset
        return "recheck_missing"
    min_met = version.shadow_since + timedelta(days=version.shadow_min_days) if version.shadow_since else None
    if min_met is None or finished < min_met or now - finished > timedelta(days=RECHECK_MAX_AGE_DAYS):
        return "recheck_stale"
    return None


def can_promote(version, snap=None) -> list:
    """Unmet conditions by stable code; empty when the version may be promoted. Reads the fields
    of the object given (promote passes the locked row)."""
    now = timezone.now()
    unmet = []
    if version.status != S.SHADOW:
        unmet.append("not_shadow")
    if not version.shadow_since or now < version.shadow_since + timedelta(days=version.shadow_min_days):
        unmet.append("too_young")
    # the population of the flips and the agreement: live rows with a would-be verdict
    compared = ShadowResult.objects.filter(version=version, origin=ShadowResult.Origin.LIVE).exclude(would_be_result="")
    if compared.count() < SHADOW_MIN_RESULTS:
        unmet.append("too_few_results")
    snap = snap or snapshot(version)
    reviewed = set(latest_reviews(version, snap))
    if any(("flip", r.case_id) not in reviewed for r in snap["critical"]):
        unmet.append("unreviewed_flips")
    delta = snap["delta"]
    if any(("campaign", c) not in reviewed for c in delta["candidate_only"] + delta["active_only"]):
        unmet.append("unreviewed_campaigns")
    code = _recheck_code(version, now)
    if code:
        unmet.append(code)
    if version.campaign_profile != _active_profile():
        span = ShadowCampaignEffect.objects.filter(version=version).aggregate(a=Min("created_at"), b=Max("created_at"))
        if span["a"] is None or span["b"] - span["a"] < timedelta(days=WINDOW_DAYS):
            unmet.append("profile_window")
    # ponytail: plain read, not locked against a retrain starting concurrently; a job started
    # after the check trains on the ledger and cannot touch the pointer.
    if running_job() is not None:
        unmet.append("job_running")
    return unmet


def _sync_or_revert(revert):
    """After commit: a 4xx reload reverts the pointer and re-raises, whatever the revert does; a
    transient failure keeps the new pointer and the beat heals the server."""
    try:
        if not serversync.sync():
            logger.warning("ai_model server sync after a pointer move failed, the beat retries")
    except serversync.ReloadRefused as refused:
        try:
            revert()
        except Exception as exc:  # never mask the refusal
            logger.warning("ai_model pointer revert failed: %s", type(exc).__name__)
        raise refused


def _refuse_unmet(target):
    unmet = can_promote(target)
    if unmet:
        raise PromotionRefused(unmet)


def promote(version, user, note=""):
    """Ruling F13: conditions re-checked under the row locks, then set_active and a server sync."""
    old_active, old_previous = registry.promote_shadow(version, user, note, _refuse_unmet)
    _sync_or_revert(lambda: registry.revert_promote(version, old_active, old_previous, user, "reload refused"))
    version.refresh_from_db()
    return version


def rollback(user, note=""):
    """The previous version becomes active again; PromotionRefused(["no_previous"]) without one."""
    picked = registry.rollback_to_previous(user, note)
    if picked is None:
        raise PromotionRefused(["no_previous"])
    target, old_active = picked

    def revert():
        if old_active is not None:
            registry.revert_rollback(target, old_active, user, "reload refused")

    _sync_or_revert(revert)
    target.refresh_from_db()
    return target


def start_shadow(version, user, note=""):
    """registry.set_shadow, then a server sync that must load the shadow. A refusal (4xx) puts
    the version back to candidate and raises ReloadRefused; a transient failure keeps the shadow
    and the beat heals the server."""
    registry.set_shadow(version, user, note)
    try:
        if not serversync.sync(shadow_must_load=True):
            logger.warning("ai_model server sync after a shadow start failed, the beat retries")
    except serversync.ReloadRefused as refused:
        try:
            registry.unshadow(version, user)
        except Exception as exc:  # never mask the refusal
            logger.warning("ai_model shadow revert failed: %s", type(exc).__name__)
        raise refused
    return version


def discard(version, user, note=""):
    """registry.discard, then a best-effort server sync (a discarded shadow leaves the server)."""
    registry.discard(version, user, note)
    try:
        if not serversync.sync():
            logger.warning("ai_model server sync after a discard failed, the beat retries")
    except serversync.ReloadRefused as exc:
        logger.warning("ai_model server sync after a discard refused: %s", type(exc).__name__)
    return version


def extend(version, days, user, note=""):
    return registry.extend_shadow(version, days, user, note)


def review(version, kind, case_id, user, note=""):
    """Append a review of one current flip or alert-delta item of the shadow; refuses an item that
    does not exist and a version that is not the shadow."""
    version.refresh_from_db(fields=["status"])
    if version.status != S.SHADOW:
        raise RegistryError(f"cannot review a {version.status} version")
    if (kind, case_id) not in _items(version):
        raise RegistryError("no such review item for this version")
    with transaction.atomic():
        row = ShadowReview.objects.create(version=version, kind=kind, case_id=case_id, user=user, note=note)
        registry.review_recorded(version, user, f"{kind} {case_id}")
    return row
