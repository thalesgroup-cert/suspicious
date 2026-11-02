"""The model registry. Every status change goes through these functions and writes a ModelEvent.

One `previous` version only: when a version becomes active, the old active becomes `previous` and
an older `previous` becomes `discarded`. Exactly one `active`: enforced by the unique
`ModelVersion.active_slot` column (MariaDB ignores partial unique indexes) plus locking reads.
"""
import dataclasses
import re
from datetime import timedelta

from django.db import IntegrityError, transaction

from common.storage import get_store

from .models import ModelEvent, ModelVersion

BUCKET = "ai-models"
PRESIGN_EXPIRY = timedelta(minutes=15)
# ponytail: a copy of training.bundle.BUNDLE_FILES + manifest.json (Django cannot import torch);
# tests/test_registry.py compares it with the training source. Upgrade: a torch-free shared module.
BUNDLE_FILE_NAMES = (
    "heads/safe_suspicious.npz", "heads/spam_dangerous.npz", "heads/safe.npz",
    "heads/unwanted.npz", "heads/dangerous.npz",
    "calibration.json", "knn_index.npz", "campaign_profile.json", "manifest.json",
)
_SHA256 = re.compile(r"[0-9a-f]{64}")
V0_MANIFEST = {
    "version_id": "v0",
    "preprocessing_version": "legacy-first128",
    "source": "legacy weights directory",
}


class RegistryError(Exception):
    pass


def bundle_prefix_for(version_id: str, job_id: str) -> str:
    return f"{BUCKET}/{version_id}/{job_id}/"


def ensure_bucket() -> None:
    """Create the bucket if absent (there is no deployment-time bootstrap for buckets)."""
    get_store().ensure_bucket(BUCKET)


def _event(version, action, user, note=""):
    ModelEvent.objects.create(version=version, action=action, user=user, note=note)


def create_candidate(version_id, bundle_prefix, manifest, manifest_sha256, campaign_profile,
                     trigger, user, job_id, parent=None):
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
    S = ModelVersion.Status
    try:
        with transaction.atomic():
            locked = _lock(version)
            if locked.status not in (S.CANDIDATE, S.SHADOW, S.PREVIOUS):
                raise RegistryError(f"cannot activate a {locked.status} version")
            # Lock the rows being demoted, oldest role first, so the slot is free before we take it.
            others = list(ModelVersion.objects.select_for_update()
                          .filter(status__in=[S.ACTIVE, S.PREVIOUS]).exclude(pk=locked.pk))
            for other in sorted(others, key=lambda o: o.status != S.PREVIOUS):
                if other.status == S.PREVIOUS:
                    other.status = S.DISCARDED
                    _event(other, "discard", user, "replaced as previous")
                else:
                    other.status, other.active_slot = S.PREVIOUS, None
                    _event(other, "demote", user, "replaced by " + locked.version_id)
                other.save(update_fields=["status", "active_slot"])
            locked.status, locked.active_slot = S.ACTIVE, 1
            locked.save(update_fields=["status", "active_slot"])
            _event(locked, "set_active", user, note)
    except IntegrityError as exc:
        raise RegistryError("another version is active") from exc
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
    """Version 0 is the legacy weights: a row without a bundle (Ruling E19). Idempotent."""
    from .campaign_profile import current_profile

    S = ModelVersion.Status
    with transaction.atomic():
        existing = ModelVersion.objects.filter(version_id="v0").first()
        if existing:
            return existing
        # ponytail: if something is already active, v0 is registered as discarded, not active.
        has_active = ModelVersion.objects.filter(status=S.ACTIVE).exists()
        version = ModelVersion.objects.create(
            version_id="v0", status=S.DISCARDED if has_active else S.ACTIVE,
            active_slot=None if has_active else 1, bundle_prefix="", manifest=dict(V0_MANIFEST),
            manifest_sha256="", campaign_profile=dataclasses.asdict(current_profile()),
            trigger=ModelVersion.Trigger.IMPORT, triggered_by=user, job_id="",
        )
        _event(version, "create_version_zero", user)
    return version


def reload_payload(version):
    """Body for /v2/reload's `active` side. Presigned with the internal address (get_store)."""
    if not version.bundle_prefix:
        return {"active": None}
    bucket, _, prefix = version.bundle_prefix.partition("/")
    store = get_store()
    return {"active": {
        "version_id": version.version_id,
        "bundle_urls": {n: store.presign_get(bucket, prefix + n, PRESIGN_EXPIRY)
                        for n in BUNDLE_FILE_NAMES},
        "manifest_sha256": version.manifest_sha256,
    }}
