"""The model registry. Every status change goes through these functions and writes a ModelEvent.

One `previous` version only: when a version becomes active, the old active becomes `previous` and
an older `previous` becomes `discarded`. Exactly one `active`: enforced by the unique
`ModelVersion.active_slot` column (MariaDB ignores partial unique indexes) plus locking reads.
"""
import dataclasses
import re
from datetime import timedelta

from django.db import IntegrityError, OperationalError, transaction
from django.db.models import Q

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
            target.status, target.active_slot = S.ACTIVE, 1
            target.save(update_fields=["status", "active_slot"])
            _event(target, "set_active", user, note)

    _retry(run)
    version.refresh_from_db()
    return version


def discard(version, user=None, note=""):
    S = ModelVersion.Status
    with transaction.atomic():
        locked = _lock(version)
        if locked.status in (S.ACTIVE, S.DISCARDED, S.FAILED):
            raise RegistryError(f"cannot discard a {locked.status} version")
        locked.status = S.DISCARDED
        locked.save(update_fields=["status"])
        _event(locked, "discard", user, note)
    version.refresh_from_db()
    return version


def fail(version, error, user=None):
    S = ModelVersion.Status
    with transaction.atomic():
        locked = _lock(version)
        if locked.status not in (S.CANDIDATE, S.SHADOW):
            raise RegistryError(f"cannot fail a {locked.status} version")
        locked.status = S.FAILED
        locked.save(update_fields=["status"])
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


def reload_payload(version):
    """Body for /v2/reload's `active` side. Presigned with the internal address (get_store)."""
    if not version.bundle_prefix:
        return {"active": None, "shadow": None}
    bucket, _, prefix = version.bundle_prefix.partition("/")
    store = get_store()
    return {"active": {
        "version_id": version.version_id,
        "bundle_urls": {n: store.presign_get(bucket, prefix + n, PRESIGN_EXPIRY)
                        for n in BUNDLE_FILE_NAMES},
        "manifest_sha256": version.manifest_sha256,
    }, "shadow": None}
