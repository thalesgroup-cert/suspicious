"""Purge objects from the `mail-previews` MinIO bucket.

Operates directly on the bucket via `list_objects` (one listing call,
using MinIO's own `.size`/`.last_modified` per object) rather than joining
through `Mail` rows — there are no Mail-side timestamps to trust for this
(a `Mail.date` header is attacker-controlled input parsed from the raw
email), and it lets this run as a plain bucket sweep independent of the
DB.

Deliberately never touches `Mail.preview_bucket` / `preview_object_key`.
Leaving those pointers in place after deleting the underlying object is
safe and intentional: `MailPreviewView` already treats a MinIO
get_object failure as a cache miss and calls `enqueue_preview_render`
to lazily re-render on next view (see api/views/mail_preview.py). If we
cleared the key instead, `sweep_missing_mail_previews` (which re-renders
every row with a blank key, unconditionally, every 10 minutes) would
re-generate every purged preview right back into existence.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Optional

from django.utils import timezone

from common.clients import get_s3_client
from mail_feeder.utils.email_preview.eml2png_renderer import _DEFAULT_PREVIEW_BUCKET

logger = logging.getLogger(__name__)


@dataclass
class PurgeResult:
    deleted_count: int = 0
    deleted_bytes: int = 0
    errors: list = field(default_factory=list)


def purge_mail_previews(
    *,
    older_than_days: Optional[int] = None,
    min_size_mb: Optional[float] = None,
    dry_run: bool = False,
    bucket: Optional[str] = None,
) -> PurgeResult:
    """Delete mail-preview objects matching age and/or size criteria.

    An object is deleted if it satisfies EITHER given criterion (age past
    `older_than_days`, or size past `min_size_mb`) — at least one of the
    two must be provided. `dry_run=True` lists/sums matches without
    deleting anything.
    """
    if older_than_days is None and min_size_mb is None:
        raise ValueError("purge_mail_previews requires older_than_days and/or min_size_mb")

    client = get_s3_client()
    bucket = bucket or _DEFAULT_PREVIEW_BUCKET

    if not client.bucket_exists(bucket):
        logger.info("purge_mail_previews: bucket %s does not exist, nothing to do", bucket)
        return PurgeResult()

    cutoff = timezone.now() - timedelta(days=older_than_days) if older_than_days else None
    min_size_bytes = int(min_size_mb * 1024 * 1024) if min_size_mb else None

    result = PurgeResult()
    for obj in client.list_objects(bucket, recursive=True):
        size = obj.size or 0
        last_modified = obj.last_modified

        matches_age = cutoff is not None and last_modified is not None and last_modified < cutoff
        matches_size = min_size_bytes is not None and size >= min_size_bytes
        if not (matches_age or matches_size):
            continue

        if not dry_run:
            try:
                client.remove_object(bucket, obj.object_name)
            except Exception:
                logger.warning(
                    "purge_mail_previews: failed to delete %s/%s",
                    bucket, obj.object_name, exc_info=True,
                )
                result.errors.append(obj.object_name)
                continue

        result.deleted_count += 1
        result.deleted_bytes += size

    logger.info(
        "purge_mail_previews: %s count=%d bytes=%d errors=%d bucket=%s",
        "would delete" if dry_run else "deleted",
        result.deleted_count, result.deleted_bytes, len(result.errors), bucket,
    )
    return result
