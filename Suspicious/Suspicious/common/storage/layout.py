"""Where a submission's objects live. Two layouts exist and ``MailArchive.bucket_name`` carries the
submission id for both: the legacy one has a bucket per submission (the id is the bucket name);
the portable prefix contract keeps every submission under ``<id>/`` in the one shared feeder bucket
(``storage.s3.feeder_bucket``)."""
from __future__ import annotations

from .base import ObjectStore


def resolve_submission_location(client: ObjectStore, submission_id: str) -> tuple[str, str] | None:
    """(bucket, key prefix) of a submission: ``(id, "")`` when a bucket of that name exists, else
    ``(feeder_bucket, "<id>/")``. None when no bucket has that name and no feeder bucket is set."""
    if client.bucket_exists(submission_id):
        return submission_id, ""
    try:
        from settings.config import get_section

        feeder_bucket = (get_section("storage.s3") or {}).get("feeder_bucket", "")
    except Exception:
        feeder_bucket = ""
    if not feeder_bucket:
        return None
    return feeder_bucket, submission_id.rstrip("/") + "/"
