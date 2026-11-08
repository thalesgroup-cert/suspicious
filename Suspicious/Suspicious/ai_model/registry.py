"""The model registry. Every status change goes through these functions and writes a ModelEvent.

One `previous` version only: when a version becomes active, the old active becomes `previous` and
an older `previous` becomes `discarded`. Exactly one `active`: enforced by the unique
`ModelVersion.active_slot` column (MariaDB ignores partial unique indexes) plus locking reads.
"""
import dataclasses
import logging
import re
from datetime import timedelta
from datetime import timezone as dt_timezone

from django.db import IntegrityError, OperationalError, transaction
from django.db.models import Q
from django.utils import timezone

from common.storage import get_store

from .models import ModelEvent, ModelVersion

BUCKET = "ai-models"
DATASET_BUCKET = "ai-datasets"  # the ledger exports the training jobs download (ai_model.export)
PRESIGN_EXPIRY = timedelta(minutes=15)
# ponytail: a copy of training.bundle.BUNDLE_FILES + manifest.json (Django cannot import torch);
# Analyzers/AIMailAnalyzer/tests/test_registry_names.py compares it. Upgrade: a shared module.
# Keep it a plain tuple of string literals (the test reads it with ast.literal_eval).
BUNDLE_FILE_NAMES = (
    "heads/safe_suspicious.npz", "heads/spam_dangerous.npz", "heads/safe.npz",
    "heads/unwanted.npz", "heads/dangerous.npz",
    "calibration.json", "knn_index.npz", "campaign_profile.json", "manifest.json",
)
logger = logging.getLogger(__name__)
MAX_SHADOW_MIN_DAYS = 365
_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")
_DEADLOCK = (1213, 1205)  # MySQL/MariaDB deadlock, lock wait timeout
_SHA256 = re.compile(r"[0-9a-f]{64}")
V0_MANIFEST = {
    "version_id": "v0",
    "preprocessing_version": "legacy-first128",
    "source": "legacy weights directory",
}


class RegistryError(Exception):
    pass


def _check_id(value, what):
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise RegistryError(f"{what} must match [A-Za-z0-9_-]{{1,64}}")
    return value


def bundle_prefix_for(version_id: str, job_id: str) -> str:
    return f"{BUCKET}/{_check_id(version_id, 'version_id')}/{_check_id(job_id, 'job_id')}/"


def ensure_bucket() -> None:
    """Create the bucket if absent (there is no deployment-time bootstrap for buckets).
    Callers that presign PUT urls (the retrain start) must call this first."""
    get_store().ensure_bucket(BUCKET)


def dataset_key_for(job_id: str) -> str:
    """One dataset per training job, in DATASET_BUCKET."""
    return f"{_check_id(job_id, 'job_id')}/dataset.npz"


def ensure_dataset_bucket() -> None:
    """ensure_bucket for DATASET_BUCKET."""
    get_store().ensure_bucket(DATASET_BUCKET)


def _event(version, action, user, note=""):
    """One event per version whose status changes."""
    ModelEvent.objects.create(version=version, action=action, user=user, note=note)


def _retry(fn):
    """Run fn (an atomic block) twice at most on a deadlock, lock timeout or active_slot clash;
    what still fails becomes RegistryError (no driver text, it can carry values)."""
    for attempt in (1, 2):
        try:
            return fn()
        except (IntegrityError, OperationalError) as exc:
            code = exc.args[0] if exc.args and isinstance(exc.args[0], int) else None
            retryable = isinstance(exc, IntegrityError) or code in _DEADLOCK
            if not retryable:
                raise
            if attempt == 2:
                raise RegistryError("registry busy or another version is active, try again") from None


def create_candidate(version_id, bundle_prefix, manifest, manifest_sha256, campaign_profile,
                     trigger, user, job_id, parent=None):
    if bundle_prefix != bundle_prefix_for(version_id, job_id):
        raise RegistryError("bundle_prefix must be ai-models/<version_id>/<job_id>/")
    if not _SHA256.fullmatch(manifest_sha256 or ""):
        raise RegistryError("manifest_sha256 must be 64 lowercase hex characters")
    if dataclasses.is_dataclass(campaign_profile):
        campaign_profile = dataclasses.asdict(campaign_profile)
    with transaction.atomic():
        version = ModelVersion.objects.create(
            version_id=version_id, status=ModelVersion.Status.CANDIDATE,
            bundle_prefix=bundle_prefix, manifest=manifest, manifest_sha256=manifest_sha256,
            campaign_profile=campaign_profile, parent=parent, trigger=trigger,
            triggered_by=user, job_id=job_id,
        )
        _event(version, "create_candidate", user)
    return version


def _lock(version):
    return ModelVersion.objects.select_for_update().get(pk=version.pk)


def set_active(version, user=None, note=""):
    """candidate, shadow, previous (rollback) and a discarded version 0 can become active.
    The old active becomes previous, an older previous becomes discarded (one previous only)."""
    S = ModelVersion.Status

    def run():
        with transaction.atomic():
            # One locking read, in pk order, for the target and both roles: no lock-order deadlock.
            rows = list(ModelVersion.objects.select_for_update().order_by("pk").filter(
                Q(pk=version.pk) | Q(status__in=(S.ACTIVE, S.PREVIOUS))))
            target = next((r for r in rows if r.pk == version.pk), None)
            if target is None:
                raise RegistryError("unknown version")
            ok = target.status in (S.CANDIDATE, S.SHADOW, S.PREVIOUS) or (
                target.status == S.DISCARDED and target.version_id == "v0")
            if not ok:
                raise RegistryError(f"cannot activate a {target.status} version")
            others = [r for r in rows if r.pk != target.pk]
            # previous -> discarded first, then active -> previous, then take the slot.
            for other in sorted(others, key=lambda o: o.status != S.PREVIOUS):
                if other.status == S.PREVIOUS:
                    other.status = S.DISCARDED
                    _event(other, "discard", user, "replaced as previous")
                else:
                    other.status, other.active_slot = S.PREVIOUS, None
                    _event(other, "demote", user, "replaced by " + target.version_id)
                other.save(update_fields=["status", "active_slot"])
            target.status, target.active_slot, target.shadow_slot = S.ACTIVE, 1, None
            target.save(update_fields=["status", "active_slot", "shadow_slot"])
            _event(target, "set_active", user, note)

    _retry(run)
    version.refresh_from_db()
    return version


def promote_shadow(version, user, note, check):
    """set_active for a promotion (ai_model.promotion). check(locked_target) runs under the row
    locks and raises to refuse. Returns (old_active, old_previous) as they were, for revert_promote."""
    S = ModelVersion.Status
    before = {}

    def run():
        with transaction.atomic():
            rows = list(ModelVersion.objects.select_for_update().order_by("pk").filter(
                Q(pk=version.pk) | Q(status__in=(S.ACTIVE, S.PREVIOUS))))
            target = next((r for r in rows if r.pk == version.pk), None)
            if target is None:
                raise RegistryError("unknown version")
            check(target)
            before.clear()
            before.update({r.status: r for r in rows if r.pk != target.pk})
            set_active(target, user, note)
            _event(target, "promote", user, note)

    _retry(run)
    version.refresh_from_db()
    return before.get(S.ACTIVE), before.get(S.PREVIOUS)


def revert_promote(target, old_active, old_previous, user=None, note=""):
    """Undo promote_shadow after the server refused the reload: target back to shadow (to
    candidate if another version became the shadow meanwhile), old_active back to active,
    old_previous (discarded by set_active) back to previous. All rows are checked first: if any
    moved meanwhile nothing is written. True when reverted."""
    S = ModelVersion.Status
    want = {target.pk: S.ACTIVE}
    if old_active is not None:
        want[old_active.pk] = S.PREVIOUS
    if old_previous is not None:
        want[old_previous.pk] = S.DISCARDED

    def run():
        with transaction.atomic():
            rows = {r.pk: r for r in ModelVersion.objects.select_for_update().order_by("pk").filter(
                Q(pk__in=want) | Q(status=S.SHADOW))}
            if any(pk not in rows or rows[pk].status != status for pk, status in want.items()):
                logger.warning("ai_model promote not reverted: the registry moved meanwhile")
                return False
            locked = rows[target.pk]
            if any(r.status == S.SHADOW for r in rows.values()):
                logger.warning("ai_model promote reverted to candidate: another version is the shadow")
                locked.status, locked.active_slot, locked.shadow_slot = S.CANDIDATE, None, None
            else:
                locked.status, locked.active_slot, locked.shadow_slot = S.SHADOW, None, 1
            locked.save(update_fields=["status", "active_slot", "shadow_slot"])
            _event(locked, "promote_reverted", user, note)
            for pk, status in ((getattr(old_active, "pk", None), S.ACTIVE),
                               (getattr(old_previous, "pk", None), S.PREVIOUS)):
                if pk is None:
                    continue
                row = rows[pk]
                row.status, row.active_slot = status, 1 if status == S.ACTIVE else None
                row.save(update_fields=["status", "active_slot"])
                _event(row, "promote_reverted", user, note)
            return True

    return _retry(run)


def rollback_to_previous(user, note=""):
    """The previous version becomes active again, picked under the row locks. Returns
    (target, old_active), or None when there is no previous."""
    S = ModelVersion.Status
    picked = []

    def run():
        with transaction.atomic():
            rows = list(ModelVersion.objects.select_for_update().order_by("pk").filter(
                status__in=(S.ACTIVE, S.PREVIOUS)))
            target = next((r for r in rows if r.status == S.PREVIOUS), None)
            if target is None:
                return
            old_active = next((r for r in rows if r.status == S.ACTIVE), None)
            set_active(target, user, note)  # refreshes target, so old_active is read first
            _event(target, "rollback", user, note)
            picked[:] = [target, old_active]

    _retry(run)
    return tuple(picked) or None


def revert_rollback(target, old_active, user=None, note=""):
    """Undo rollback_to_previous: a swap back, only if both rows are where it left them."""
    S = ModelVersion.Status

    def run():
        with transaction.atomic():
            rows = {r.pk: r for r in ModelVersion.objects.select_for_update().order_by("pk").filter(
                pk__in=(target.pk, old_active.pk))}
            if (getattr(rows.get(target.pk), "status", None) != S.ACTIVE
                    or getattr(rows.get(old_active.pk), "status", None) != S.PREVIOUS):
                logger.warning("ai_model rollback not reverted: the registry moved meanwhile")
                return False
            set_active(old_active, user, note)
            _event(old_active, "rollback_reverted", user, note)
            return True

    return _retry(run)


def extend_shadow(version, days, user=None, note=""):
    """Raise the shadow's minimum period (shadow_min_days); it never goes down."""
    with transaction.atomic():
        locked = _lock(version)
        if locked.status != ModelVersion.Status.SHADOW:
            raise RegistryError(f"cannot extend a {locked.status} version")
        if (not isinstance(days, int) or isinstance(days, bool)
                or not locked.shadow_min_days < days <= MAX_SHADOW_MIN_DAYS):
            raise RegistryError(f"days must be above {locked.shadow_min_days} and at most {MAX_SHADOW_MIN_DAYS}")
        locked.shadow_min_days = days
        locked.save(update_fields=["shadow_min_days"])
        _event(locked, "extend", user, f"{days} days" + (f": {note}" if note else ""))
    version.refresh_from_db()
    return version


def discard(version, user=None, note=""):
    S = ModelVersion.Status
    with transaction.atomic():
        locked = _lock(version)
        if locked.status in (S.ACTIVE, S.DISCARDED, S.FAILED):
            raise RegistryError(f"cannot discard a {locked.status} version")
        locked.status, locked.shadow_slot = S.DISCARDED, None
        locked.save(update_fields=["status", "shadow_slot"])
        _event(locked, "discard", user, note)
    version.refresh_from_db()
    return version


def set_shadow(version, user=None, note=""):
    """A gate-eligible candidate becomes the one shadow; its seeding (Ruling F8) is queued once
    the change commits."""
    S = ModelVersion.Status

    def run():
        with transaction.atomic():
            locked = _lock(version)
            if locked.status != S.CANDIDATE:
                raise RegistryError(f"cannot shadow a {locked.status} version")
            if locked.manifest.get("eligible") is not True:
                raise RegistryError("the version did not pass the gate")
            if ModelVersion.objects.select_for_update().filter(status=S.SHADOW).exists():
                raise RegistryError("another version is the shadow, discard it first")
            locked.status, locked.shadow_slot = S.SHADOW, 1
            locked.shadow_since = timezone.now()
            locked.save(update_fields=["status", "shadow_slot", "shadow_since"])
            _event(locked, "set_shadow", user, note)
            transaction.on_commit(lambda: _queue_seeding(locked.version_id))

    _retry(run)
    version.refresh_from_db()
    return version


def recheck_started(version, user, job_id):
    """Ruling F11: a gate recheck of this version was posted (retrain.start_recheck)."""
    _event(version, "start_recheck", user, job_id)


def review_recorded(version, user, note):
    """A shadow review was appended (promotion.review, inside its transaction)."""
    _event(version, "review", user, note)


def record_recheck(version, job_id, passed, finished_at):
    """Store a finished recheck as {job_id, passed, finished_at (ISO, UTC)}. Only the shadow
    version takes one: a version discarded or promoted meanwhile is left as it is."""
    with transaction.atomic():
        locked = _lock(version)
        if locked.status != ModelVersion.Status.SHADOW:
            raise RegistryError(f"cannot record a recheck on a {locked.status} version")
        locked.recheck = {"job_id": job_id, "passed": bool(passed),
                          "finished_at": finished_at.astimezone(dt_timezone.utc).isoformat()}
        locked.save(update_fields=["recheck"])
        _event(locked, "recheck", None, f"{job_id} {'passed' if passed else 'failed'}")
    version.refresh_from_db()
    return version


def _queue_seeding(version_id):
    from .tasks import seed_shadow

    seed_shadow.delay(version_id)


def fail(version, error, user=None):
    S = ModelVersion.Status
    with transaction.atomic():
        locked = _lock(version)
        if locked.status not in (S.CANDIDATE, S.SHADOW):
            raise RegistryError(f"cannot fail a {locked.status} version")
        locked.status, locked.shadow_slot = S.FAILED, None
        locked.save(update_fields=["status", "shadow_slot"])
        _event(locked, "fail", user, str(error)[:500])
    version.refresh_from_db()
    return version


def ensure_version_zero(user=None):
    """Version 0 is the legacy weights: a row without a bundle (Ruling E19). Idempotent. It is
    active when nothing is, else previous when no previous exists, else discarded; set_active
    accepts a discarded v0, so it stays a rollback target."""
    from .campaign_profile import current_profile

    S = ModelVersion.Status

    def run():
        with transaction.atomic():
            existing = ModelVersion.objects.filter(version_id="v0").first()
            if existing:
                return existing
            held = set(ModelVersion.objects.select_for_update().order_by("pk")
                       .filter(status__in=(S.ACTIVE, S.PREVIOUS)).values_list("status", flat=True))
            status = S.ACTIVE if S.ACTIVE not in held else (
                S.PREVIOUS if S.PREVIOUS not in held else S.DISCARDED)
            version = ModelVersion.objects.create(
                version_id="v0", status=status, active_slot=1 if status == S.ACTIVE else None,
                bundle_prefix="", manifest=dict(V0_MANIFEST), manifest_sha256="",
                campaign_profile=dataclasses.asdict(current_profile()),
                trigger=ModelVersion.Trigger.IMPORT, triggered_by=user, job_id="",
            )
            _event(version, "create_version_zero", user)
            return version

    try:
        return _retry(run)
    except RegistryError:
        existing = ModelVersion.objects.filter(version_id="v0").first()
        if existing:
            return existing
        raise


def _bundle(version):
    """The /v2/reload entry of one version. Presigned with the internal address (get_store)."""
    if version is None or not version.bundle_prefix:
        return None
    bucket, _, prefix = version.bundle_prefix.partition("/")
    store = get_store()
    return {
        "version_id": version.version_id,
        "bundle_urls": {n: store.presign_get(bucket, prefix + n, PRESIGN_EXPIRY)
                        for n in BUNDLE_FILE_NAMES},
        "manifest_sha256": version.manifest_sha256,
    }


def reload_payload(active, shadow=None):
    """Body for /v2/reload. Version 0 (no bundle) is `active: null`; no shadow is `shadow: null`."""
    return {"active": _bundle(active), "shadow": _bundle(shadow)}
