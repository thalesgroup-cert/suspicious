"""
MinIO helpers for the AI analyzer.
"""
from __future__ import annotations

import logging
from typing import Optional, Tuple

from common.storage import ObjectStore, StoreError
from common.storage.layout import resolve_submission_location

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


# Ceiling on one mail text / headers read. The AI inference server cuts the body at
# INFERENCE_MAX_MAIL_CHARS characters (200,000 by default, Analyzers/AIMailAnalyzer/inference_server/
# server.py); at the worst case of 4 bytes per character that is 800 KB, so 4 MiB leaves five
# times the headroom should that limit be raised. A cut inside a character decodes to U+FFFD.
MAIL_TEXT_MAX_BYTES = 4 * 1024 * 1024


# ── Internal helpers ──────────────────────────────────────────────────────────

def _read_object_safe(client: ObjectStore, bucket: str, key: str, limit: int = -1) -> bytes:
    """
    Read and return the content of a MinIO object (all of it, or at most
    ``limit`` bytes), closing the response regardless of whether an
    exception occurs.
    """
    with client.open(bucket, key) as stream:
        return stream.read(limit)


def _find_mail_bucket(client: ObjectStore, mail_id: str) -> Optional[str]:
    """
    Return the bucket that holds this mail's objects.

    Bucket names are ``<reporter>-submission-<timestamp>`` and the mail id
    starts with that timestamp, so reporters whose submissions land in the same
    second share the suffix. Match on the suffix, then keep the candidate that
    really contains ``<mail_id>/``.
    """
    short_id = mail_id.split("-")[0]
    try:
        for bucket in client.list_buckets():
            if not bucket.endswith("-%s" % short_id):
                continue
            if any(True for _ in client.list(bucket, prefix="%s/" % mail_id)):
                return bucket
    except StoreError as exc:
        if exc.code != "not_found":
            raise
        logger.error("Error listing MinIO buckets while searching for mail %s: %s", mail_id, exc)
    return None


def find_mail_prefix(client: ObjectStore, mail_id: str, bucket_name: str = "") -> Optional[Tuple[str, str]]:
    """(bucket, ``<...><mail_id>/``) holding the mail's objects, None when no store location does.
    ``bucket_name`` is ``MailArchive.bucket_name``: the submission is looked up as
    fetch_mail_text_from_minio does, then by the mail id's timestamp suffix. A store error other
    than not_found propagates."""
    location = resolve_submission_location(client, bucket_name) if bucket_name else None
    if location:
        bucket, base = location
        prefix = "%s%s/" % (base, mail_id)
        try:
            if any(True for _ in client.list(bucket, prefix=prefix)):
                return bucket, prefix
        except StoreError as exc:
            if exc.code != "not_found":
                raise
    bucket = _find_mail_bucket(client, mail_id)
    return (bucket, "%s/" % mail_id) if bucket else None


# ── Public API ────────────────────────────────────────────────────────────────

def fetch_mail_files_from_minio(
    client: ObjectStore,
    mail_id: str,
) -> Tuple[str, str, str, str]:
    """
    Fetch .headers, .eml, .txt, and .html files for a mail from MinIO.

    Returns (headers, eml, txt, html) — any file not found is "".
    """
    headers = eml = txt = html = ""
    bucket = _find_mail_bucket(client, mail_id)
    if not bucket:
        logger.warning("fetch_mail_files: no bucket found for mail %s.", mail_id)
        return headers, eml, txt, html

    try:
        objects = client.list(bucket, prefix=mail_id, recursive=True)
        for obj in objects:
            name = obj.name
            try:
                content = _read_object_safe(client, bucket, name).decode("utf-8", errors="replace")
                if name.endswith(".headers"):
                    headers = content
                elif name.endswith(".eml"):
                    eml = content
                elif name.endswith(".txt"):
                    txt = content
                elif name.endswith(".html"):
                    html = content
            except Exception as exc:
                logger.error("fetch_mail_files: could not read %s: %s", name, exc)

    except StoreError as exc:
        if exc.code != "not_found":
            raise
        logger.error("fetch_mail_files: error fetching files for mail %s: %s", mail_id, exc)

    return headers, eml, txt, html


def _read_text_parts(client: ObjectStore, bucket: str, prefix: str, max_bytes: int) -> dict[str, str]:
    """{".headers": text, ".txt": text} for the objects directly under ``prefix`` (those that exist),
    each read capped at ``max_bytes``. {} when the bucket or an object is gone (not_found)."""
    try:
        wanted: dict[str, str] = {}
        for obj in client.list(bucket, prefix=prefix, recursive=True):
            rel = obj.name[len(prefix):]
            if "/" in rel:
                continue
            for suffix in (".headers", ".txt"):
                if rel.endswith(suffix):
                    wanted.setdefault(suffix, obj.name)
        return {
            suffix: _read_object_safe(client, bucket, name, max_bytes).decode("utf-8", errors="replace")
            for suffix, name in wanted.items()
        }
    except StoreError as exc:
        if exc.code != "not_found":
            raise
        logger.warning("fetch_mail_text: %s/%s not found in the store: %s", bucket, prefix, exc)
        return {}


def fetch_mail_text_from_minio(
    client: ObjectStore,
    mail_id: str,
    bucket_name: str = "",
    max_bytes: int = MAIL_TEXT_MAX_BYTES,
) -> Tuple[str, str]:
    """
    Fetch the mail's ``.headers`` and ``.txt`` objects from MinIO.

    ``bucket_name`` is ``MailArchive.bucket_name``, the submission id. With it the mail is looked
    up where common.storage.layout puts the submission: ``<mail_id>/`` in a bucket of that name
    (legacy), else ``<bucket_name>/<mail_id>/`` in the feeder bucket (prefix contract). Without it,
    or when nothing is there, the bucket is found by the mail id's timestamp suffix.

    Returns (headers, txt); a part that is not there, or a mail the store does not hold, is "".
    Unlike fetch_mail_files_from_minio this opens nothing else (the .eml and .html can be
    tens of MB), looks only at objects directly under the mail's prefix (``attachments/`` may
    hold .txt files) and reads at most ``max_bytes`` of each. A store error other than
    not_found propagates.
    """
    parts: dict[str, str] = {}
    location = resolve_submission_location(client, bucket_name) if bucket_name else None
    if location:
        bucket, base = location
        parts = _read_text_parts(client, bucket, "%s%s/" % (base, mail_id), max_bytes)
    if not parts:
        bucket = _find_mail_bucket(client, mail_id)
        if bucket:
            parts = _read_text_parts(client, bucket, "%s/" % mail_id, max_bytes)
    return parts.get(".headers", ""), parts.get(".txt", "")
