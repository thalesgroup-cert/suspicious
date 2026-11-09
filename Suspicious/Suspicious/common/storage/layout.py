"""Where a submission's objects live. Two layouts exist and ``MailArchive.bucket_name`` carries the
submission id for both: the legacy one has a bucket per submission (the id is the bucket name);
the portable prefix contract keeps every submission under ``<id>/`` in the one shared feeder bucket
(``storage.s3.feeder_bucket``)."""
from __future__ import annotations

from .base import ObjectStore, StoreError


def resolve_submission_location(client: ObjectStore, submission_id: str) -> tuple[str, str] | None:
    """(bucket, key prefix) of a submission: ``(id, "")`` when a bucket of that name exists, else
    ``(feeder_bucket, "<id>/")``. None when no bucket has that name and no feeder bucket is set."""
    try:
        exists = client.bucket_exists(submission_id)
    except StoreError as exc:
        # A prefix-layout id keeps the reporter's uppercase and "_"; S3 refuses such a bucket name
        # (invalid). A name S3 cannot hold is not our bucket. Any other error propagates.
        if exc.code != "invalid":
            raise
        exists = False
    if exists:
        return submission_id, ""
    try:
        from settings.config import get_section

        feeder_bucket = (get_section("storage.s3") or {}).get("feeder_bucket", "")
    except Exception:
        feeder_bucket = ""
    if not feeder_bucket:
        return None
    return feeder_bucket, submission_id.rstrip("/") + "/"
