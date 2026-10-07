"""
MinIO helpers for the AI analyzer.
"""
from __future__ import annotations

import logging
from typing import Optional, Tuple

from minio import Minio
from minio.error import S3Error

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


# ── Internal helpers ──────────────────────────────────────────────────────────

def _read_object_safe(client: Minio, bucket: str, key: str) -> bytes:
    """
    Read and return the full content of a MinIO object, closing the
    response regardless of whether an exception occurs.
    """
    response = client.get_object(bucket, key)
    try:
        return response.read()
    finally:
        response.close()
        response.release_conn()


def _find_mail_bucket(client: Minio, mail_id: str) -> Optional[str]:
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
            if not bucket.name.endswith("-%s" % short_id):
                continue
            if any(True for _ in client.list_objects(bucket.name, prefix="%s/" % mail_id)):
                return bucket.name
    except S3Error as exc:
        logger.error("Error listing MinIO buckets while searching for mail %s: %s", mail_id, exc)
    return None


# ── Public API ────────────────────────────────────────────────────────────────

def fetch_mail_files_from_minio(
    client: Minio,
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
        objects = client.list_objects(bucket, prefix=mail_id, recursive=True)
        for obj in objects:
            name = obj.object_name
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

    except S3Error as exc:
        logger.error("fetch_mail_files: error fetching files for mail %s: %s", mail_id, exc)

    return headers, eml, txt, html