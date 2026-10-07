"""
MinIO helpers for the AI analyzer.
"""
from __future__ import annotations

import io
import logging
import zipfile
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

def build_mail_zip_from_minio(
    client: Minio,
    mail_id: str,
    reporter_name: str,
) -> Tuple[str, bytes]:
    """
    Build an in-memory ZIP of all objects stored under <mail_id>/ and
    return (filename, zip_bytes).

    Returns ("", b"") when the bucket cannot be found or is empty.
    """
    bucket = _find_mail_bucket(client, mail_id)
    if not bucket:
        logger.warning("build_mail_zip: no bucket found for mail %s.", mail_id)
        return "", b""

    prefix     = "%s/" % mail_id
    zip_buffer = io.BytesIO()

    written = 0
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        try:
            objects = client.list_objects(bucket, prefix=prefix, recursive=True)
            for obj in objects:
                try:
                    content = _read_object_safe(client, bucket, obj.object_name)
                    arcname = obj.object_name.replace(prefix, "", 1)
                    zf.writestr(arcname, content)
                    written += 1
                except Exception as exc:
                    logger.error(
                        "build_mail_zip: could not read %s from %s: %s",
                        obj.object_name, bucket, exc,
                    )
        except S3Error as exc:
            logger.error("build_mail_zip: error listing objects for mail %s: %s", mail_id, exc)
            return "", b""

    if not written:
        logger.warning("build_mail_zip: nothing readable for mail %s in %s.", mail_id, bucket)
        return "", b""

    zip_buffer.seek(0)
    safe_reporter = reporter_name.replace(" ", "_").replace("/", "_")
    filename      = "%s_%s.zip" % (safe_reporter, mail_id)
    return filename, zip_buffer.read()


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