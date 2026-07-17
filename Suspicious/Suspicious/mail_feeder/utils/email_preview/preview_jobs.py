"""Shared mail-preview (re)generation, sourced from the MinIO archive.

Extracted from the `regenerate_mail_previews` management command so the
same logic backs the command, the `render_mail_preview` Celery task, and
the `sweep_missing_mail_previews` beat sweeper. All IO (MinIO, wkhtmltopdf)
is reached through an injected `fetch_eml` callable + `renderer` object,
so the orchestration is unit-testable with fakes.
"""
from __future__ import annotations

import logging
import os
import tempfile
from pathlib import Path
from typing import Callable, Optional

from mail_feeder.models import Mail, MailArchive

logger = logging.getLogger(__name__)


def build_storage_client():
    """Build a MinIO StorageClient from the shared ``storage.s3`` runtime config."""
    from api.storage import StorageClient

    storage = StorageClient()
    if not getattr(storage, "client", None):
        raise RuntimeError("MinIO client initialisation failed")
    return storage


def fetch_eml_bytes(storage, bucket_name: str) -> Optional[bytes]:
    """Stream the previewable .eml from the archive.

    Resolves both storage layouts. Legacy: bucket-per-submission, where
    ``bucket_name`` is a real bucket holding the .eml at the root. Portable
    prefix contract: one shared feeder bucket where the submission id is a
    *prefix* — MailArchive.bucket_name still carries that id, so when no
    bucket of that name exists we fall back to the feeder bucket + prefix
    (otherwise list_objects raises NoSuchBucket and no preview renders).

    The archive holds both the reporter wrapper (`user_submission.eml` /
    `reporter-submission.eml`) and the reported message (any other .eml).
    The preview must render the reported message, so we pick the first
    non-wrapper .eml and only fall back to a wrapper when nothing else
    exists (legacy submissions before the split).
    """
    if storage.client.bucket_exists(bucket_name):
        bucket, prefix = bucket_name, ""
    else:
        try:
            from settings.config import get_section
            feeder_bucket = (get_section("storage.s3") or {}).get("feeder_bucket", "")
        except Exception:
            feeder_bucket = ""
        if not feeder_bucket:
            return None
        bucket = feeder_bucket
        prefix = bucket_name.rstrip("/") + "/"

    objects = list(storage.client.list_objects(bucket, prefix=prefix, recursive=True))
    eml_keys = [
        getattr(o, "object_name", "") or "" for o in objects
        if (getattr(o, "object_name", "") or "").lower().endswith(".eml")
    ]
    if not eml_keys:
        return None

    _WRAPPERS = ("user_submission.eml", "reporter-submission.eml")
    non_wrapper = [
        k for k in eml_keys
        if not k.lower().endswith(_WRAPPERS)
    ]
    eml_key = sorted(non_wrapper)[0] if non_wrapper else sorted(eml_keys)[0]

    response = None
    try:
        response = storage.client.get_object(bucket, eml_key)
        return response.read()
    finally:
        if response is not None:
            try:
                response.close()
                response.release_conn()
            except Exception:
                pass


def enqueue_preview_render(mail_id: int, *, dedup_window: int = 300) -> bool:
    """Enqueue `render_mail_preview` for one mail, at most once per window.

    Used by MailPreviewView to lazily (re)generate a preview on a cache
    miss — e.g. the MinIO object vanished — without blocking the request
    or hammering the worker when many `<img>` tags retry at once. A short
    Redis/cache lock (`preview_render:<id>`) collapses the burst to a
    single enqueue. Returns True when enqueued, False when a recent
    enqueue is still in flight.
    """
    from django.core.cache import cache
    from tasp.tasks import render_mail_preview

    if not cache.add(f"preview_render:{mail_id}", 1, timeout=dedup_window):
        return False
    render_mail_preview.delay(mail_id)
    return True


def regenerate_mail_preview(
    mail: Mail,
    *,
    fetch_eml: Callable[[MailArchive], Optional[bytes]],
    renderer,
) -> str:
    """Render + store the preview for one mail. No stdout, no enqueue.

    Returns one of:
      - "ok"      preview rendered and (bucket, key) persisted on the row
      - "skipped" no fetchable archive, or no .eml in the bucket
      - "failed"  fetch raised, renderer produced nothing, or the upload
                  did not persist a key
    """
    archive = MailArchive.objects.filter(mail=mail).first()
    if archive is None or not archive.bucket_name:
        return "skipped"

    try:
        eml_bytes = fetch_eml(archive)
    except Exception as exc:
        logger.warning(
            "render_mail_preview: mail#%s fetch failed bucket=%s err=%s",
            mail.pk, archive.bucket_name, exc,
        )
        return "failed"

    if not eml_bytes:
        return "skipped"

    png_bytes = _render_eml_bytes_to_png(eml_bytes, renderer)
    if not png_bytes:
        return "failed"

    renderer.save_preview_to_mail(mail, png_bytes)
    if not mail.preview_object_key:
        return "failed"
    return "ok"


def _render_eml_bytes_to_png(eml_bytes: bytes, renderer) -> Optional[bytes]:
    """Write eml bytes to a temp file and hand the path to the renderer."""
    with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as fp:
        fp.write(eml_bytes)
        tmp_path = Path(fp.name)
    try:
        return renderer.render_eml_path_to_png_bytes(tmp_path)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
