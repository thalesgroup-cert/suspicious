import email as stdlib_email
import io
import json
import os
import re
import shutil
import logging
from datetime import datetime, timezone
from typing import Optional
from minio import Minio
from django.core.cache import cache
from minio.commonconfig import Tags
from pathlib import Path

from .utils import safe_execution, load_config, ensure_dir
from .models import CronConfig
from mail_feeder.minio_submission.minio import MinioEmailService

logger = logging.getLogger("tasp.cron.fetch_and_process_emails")

CONFIG_PATH = "/app/settings.json"

MANIFEST_OBJECT_NAME = "metadata.json"
SUBMISSION_EML_SUFFIX = "submission.eml"
EMAIL_DIR_PATTERN = re.compile(r"^\d{12}-[a-f0-9]+$")


# ---------------------------------------------------------------------------
# MinIO client
# ---------------------------------------------------------------------------

def _init_minio_client(minio_conf) -> Optional[Minio]:
    try:
        return Minio(
            minio_conf.endpoint,
            access_key=minio_conf.access_key,
            secret_key=minio_conf.secret_key,
            secure=minio_conf.secure,
        )
    except Exception:
        logger.exception("MinIO client initialization failed")
        return None


# ---------------------------------------------------------------------------
# Path safety
# ---------------------------------------------------------------------------

def _safe_object_name(raw_name: str) -> str:
    """
    Sanitize a MinIO object name before using it as a filesystem path component.
    Prevents path traversal via crafted object names (e.g. '../../etc/passwd').
    Raises ValueError if the sanitized name is empty or escapes the prefix.
    """
    normalized = os.path.normpath(raw_name.replace("\\", "/")).lstrip("/")
    if not normalized or normalized.startswith(".."):
        raise ValueError(f"Unsafe MinIO object name rejected: {raw_name!r}")
    return normalized


# ---------------------------------------------------------------------------
# Manifest helpers
# ---------------------------------------------------------------------------

def _extract_reported_by(submission_eml_path: str) -> str:
    """
    Extract the reporter's bare email address from the submission wrapper .eml.
    Returns an empty string if parsing fails — never raises.
    """
    try:
        with open(submission_eml_path, "rb") as f:
            msg = stdlib_email.message_from_bytes(f.read())
        from_header = msg.get("From", "")
        match = re.search(r"[\w.+\-]+@[\w.\-]+\.\w+", from_header)
        return match.group(0) if match else ""
    except Exception:
        logger.warning("Could not parse reported_by from %s", submission_eml_path)
        return ""


def _collect_manifest_fields(
    bucket_path: str,
    submission_path: str,
    bucket_name: str,
) -> dict:
    """
    Walk the already-downloaded bucket directory and build the manifest payload.

    Returns a dict ready to be JSON-serialised as metadata.json:
      submission_id     — bucket name (stable unique ID for this submission)
      reported_by       — From address extracted from the submission wrapper .eml
      submitted_at      — UTC ISO-8601 timestamp of manifest creation
      emails_to_analyze — relative object keys for .eml files to analyse
                          (excludes the wrapper submission.eml itself)
      attachments       — relative object keys for every other file
    """
    reported_by = _extract_reported_by(submission_path)
    emails_to_analyze: list[str] = []
    attachments: list[str] = []

    for dirpath, _, filenames in os.walk(bucket_path):
        for filename in filenames:
            full = os.path.join(dirpath, filename)
            # Object key = path relative to the bucket root, using forward slashes
            rel = os.path.relpath(full, bucket_path).replace(os.sep, "/")

            # Skip the wrapper submission email — it is the reporter vehicle,
            # not an email to be analysed.
            if filename.endswith(SUBMISSION_EML_SUFFIX):
                continue
            elif filename.endswith(".eml"):
                emails_to_analyze.append(rel)
            else:
                attachments.append(rel)

    return {
        "submission_id": bucket_name,
        "reported_by": reported_by,
        "submitted_at": datetime.now(tz=timezone.utc).isoformat(),
        "emails_to_analyze": emails_to_analyze,
        "attachments": attachments,
    }


def _write_manifest(
    client: Minio,
    bucket_name: str,
    manifest: dict,
    bucket_path: str,
) -> None:
    """
    Write metadata.json to the MinIO bucket AND save a local copy under
    bucket_path so that MinioEmailService can read it from the filesystem
    without an extra round-trip.

    Logs a warning on failure — never raises, so a manifest write failure
    does not abort the rest of the processing loop.
    """
    raw = json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8")

    # Write to MinIO
    try:
        client.put_object(
            bucket_name=bucket_name,
            object_name=MANIFEST_OBJECT_NAME,
            data=io.BytesIO(raw),
            length=len(raw),
            content_type="application/json",
        )
        logger.debug(
            "Manifest written to MinIO bucket %s (%d eml(s), reported_by=%s)",
            bucket_name,
            len(manifest.get("emails_to_analyze", [])),
            manifest.get("reported_by", ""),
        )
    except Exception:
        logger.warning(
            "Failed to write manifest to MinIO bucket %s — "
            "MinioScanner will reconcile on next processor run.",
            bucket_name,
            exc_info=True,
        )

    # Write local copy alongside downloaded objects so MinioEmailService
    # can load it from the filesystem without re-fetching from MinIO.
    local_path = os.path.join(bucket_path, MANIFEST_OBJECT_NAME)
    try:
        with open(local_path, "wb") as f:
            f.write(raw)
    except OSError:
        logger.warning("Could not write local manifest copy to %s", local_path, exc_info=True)


# ---------------------------------------------------------------------------
# Main entrypoint
# ---------------------------------------------------------------------------

def fetch_and_process_emails(config_path: str = CONFIG_PATH) -> None:
    """
    Main cron entry point.

    Downloads all objects from MinIO buckets tagged Status=To Do, writes a
    metadata.json manifest, then hands each email subdirectory to
    MinioEmailService for processing. Tags the bucket as Done on success.
    """
    import time
    cfg = load_config(config_path)
    base_temp = cfg.temp_dir
    ensure_dir(base_temp)
    logger.info("Starting email fetch job")
    try:
        _process_minio_buckets(cfg, base_temp)
    finally:
        try:
            shutil.rmtree(base_temp)
        except Exception:
            logger.exception("Failed to remove temp dir")
    logger.info("Email fetch job completed")
    try:
        from api.metrics import email_feeder_last_poll_seconds
        email_feeder_last_poll_seconds.set(time.time())
    except Exception:
        pass


def _process_minio_buckets(cfg: CronConfig, base_path: str) -> None:
    client = _init_minio_client(cfg.s3)
    if not client:
        return

    minio_processor = MinioEmailService()

    for bucket in client.list_buckets():
        with safe_execution(f"process bucket {bucket.name}"):

            try:
                tags = client.get_bucket_tags(bucket.name)
                if tags.get("Status") != "To Do":
                    continue
            except Exception:
                continue

            lock_key = f"lock:minio_bucket:{bucket.name}"
            if not cache.add(lock_key, "1", timeout=900):
                logger.debug("Bucket %s already locked, skipping", bucket.name)
                continue

            try:
                logger.debug("Processing bucket %s", bucket.name)

                try:
                    processing_tags = Tags.new_bucket_tags()
                    processing_tags["Status"] = "Processing"
                    client.set_bucket_tags(bucket.name, processing_tags)
                except Exception:
                    logger.warning("Failed to set Processing tag for %s", bucket.name)

                bucket_path = os.path.join(base_path, bucket.name)
                ensure_dir(bucket_path)

                submission_path: Optional[str] = None

                for obj in client.list_objects(bucket.name, recursive=True):
                    try:
                        safe_name = _safe_object_name(obj.object_name)
                    except ValueError:
                        logger.warning(
                            "Skipping unsafe object name %r in bucket %s",
                            obj.object_name, bucket.name,
                        )
                        continue

                    dst = os.path.join(bucket_path, safe_name)
                    ensure_dir(os.path.dirname(dst))
                    client.fget_object(bucket.name, obj.object_name, dst)

                    if obj.object_name.endswith(SUBMISSION_EML_SUFFIX):
                        submission_path = dst

                if not submission_path:
                    logger.debug("No submission.eml found in %s — skipping", bucket.name)
                    continue

                manifest = _collect_manifest_fields(bucket_path, submission_path, bucket.name)
                _write_manifest(client, bucket.name, manifest, bucket_path)

                logger.debug(
                    "Bucket %s: %d email(s), reported_by=%s",
                    bucket.name,
                    len(manifest["emails_to_analyze"]),
                    manifest["reported_by"],
                )

                for entry in os.scandir(bucket_path):
                    if not (entry.is_dir() and EMAIL_DIR_PATTERN.match(entry.name)):
                        continue

                    shutil.copy(
                        submission_path,
                        os.path.join(entry.path, "user_submission.eml"),
                    )

                    shutil.make_archive(entry.path, "gztar", entry.path)

                    minio_processor.process_emails_from_minio_workdir(
                        entry.path,
                        bucket.name,
                        reported_by=manifest["reported_by"],
                    )

                try:
                    done_tags = Tags.new_bucket_tags()
                    done_tags["Status"] = "Done"
                    client.set_bucket_tags(bucket.name, done_tags)
                except Exception:
                    logger.exception("Failed to tag bucket %s as Done", bucket.name)

            except Exception:
                logger.exception("Error while processing bucket %s", bucket.name)

                try:
                    error_tags = Tags.new_bucket_tags()
                    error_tags["Status"] = "To Do"
                    client.set_bucket_tags(bucket.name, error_tags)
                except Exception:
                    logger.warning("Failed to rollback status for %s", bucket.name)

            finally:
                # release
                cache.delete(lock_key)