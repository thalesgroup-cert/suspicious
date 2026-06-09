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
    """Build a MinIO StorageClient from the runtime config accessor.

    Reuses the same loader the downloads view uses so callers work in any
    deployment without extra wiring. Raises on misconfiguration.
    """
    from api.views.downloads import load_minio_config
    from api.storage import StorageClient

    cfg = load_minio_config()
    if not cfg:
        raise RuntimeError("Could not load MinIO config via accessor")
    storage = StorageClient(cfg)
    if not getattr(storage, "client", None):
        raise RuntimeError("MinIO client initialisation failed")
    return storage


def fetch_eml_bytes(storage, bucket_name: str) -> Optional[bytes]:
    """Stream the previewable .eml from the archive bucket.

    Buckets typically contain both the reporter wrapper
    (`user_submission.eml`) and the actual reported message (any other
    .eml). The preview must always render the reported message, never the
    wrapper. We pick the first non-wrapper .eml and only fall back to
    user_submission.eml when nothing else exists (legacy submissions
    before the split).
    """
    objects = list(storage.client.list_objects(bucket_name, recursive=True))
    eml_keys = [
        getattr(o, "object_name", "") or "" for o in objects
        if (getattr(o, "object_name", "") or "").lower().endswith(".eml")
    ]
    if not eml_keys:
        return None

    non_wrapper = [
        k for k in eml_keys
        if not k.lower().endswith("user_submission.eml")
    ]
    eml_key = non_wrapper[0] if non_wrapper else eml_keys[0]

    response = None
    try:
        response = storage.client.get_object(bucket_name, eml_key)
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
