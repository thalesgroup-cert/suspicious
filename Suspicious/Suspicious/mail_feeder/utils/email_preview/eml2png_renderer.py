"""
Render an .eml/.msg file to a PNG preview.

Pipeline: stdlib `email` parses the message, we build a sanitised HTML
wrapper (headers + body), then post it to the `mail_renderer` service, an
isolated headless-Chromium container with no route out (see
`mail-renderer/server.py`), which returns the PNG. This replaced
wkhtmltoimage, an unmaintained 2020 WebKit that ran inside this image.

Storage
-------
Rendered PNGs are uploaded directly to MinIO under a dedicated
`mail-previews` bucket (key = `<mail.pk>.png`). The Mail row records
the (bucket, key) pair so MailPreviewView can stream straight from
MinIO without going through Django's storage backend (which used to
fall back to /media/... URLs the admin then tried to GET and 404'd
on in production).
"""
from __future__ import annotations

import email
import io
import logging
import os
from email.message import EmailMessage
from email.policy import default as email_default_policy
from html import escape
from pathlib import Path
from typing import Optional

import nh3
import requests
from django.conf import settings

from common.storage import get_store
from mail_feeder.utils.email_preview.html_sanitizer import sanitize_email_html

logger = logging.getLogger(__name__)

_DEFAULT_PREVIEW_BUCKET = "mail-previews"


_RENDER_WIDTH_PX = 900

# The renderer clips every screenshot to the content, at most 4000px tall, and
# answers with a compressed PNG (a typical mail is tens of KB). This is the
# belt-and-braces guard on top: drop a render that still comes back oversized
# rather than store it; MailPreviewView already treats a missing preview as a
# 404 + lazy re-render trigger, so this degrades like any other render failure.
_MAX_PNG_BYTES = 15 * 1024 * 1024

# Isolated renderer (compose service `mail_renderer`). Connect fast, wait longer
# than the renderer's own per-request limit (30 s) so its answer is the one we get.
_RENDERER_URL = os.environ.get("MAIL_RENDERER_URL", "http://mail_renderer:8080")
_RENDER_TIMEOUT = (3, 40)

_VISIBLE_HEADERS = ("From", "To", "Cc", "Subject", "Date", "Reply-To")

# Inline !important wins over any stylesheet rule in the (sanitised) body, so a
# mail cannot hide the header rows the analyst relies on.
_KEEP_VISIBLE = "visibility:visible !important;display:{} !important"

class Eml2PngRenderer:
    """Render an .eml file to a PNG preview via stdlib email + the mail_renderer service."""

    # Public API

    def render_eml_path_to_png_bytes(self, eml_path: Path) -> Optional[bytes]:
        if not eml_path.exists():
            logger.warning("EML file not found: %s", eml_path)
            return None

        try:
            with eml_path.open("rb") as fp:
                msg = email.message_from_binary_file(fp, policy=email_default_policy)
        except Exception:
            logger.exception("Failed to parse EML file %s", eml_path)
            return None

        html = self._build_preview_html(msg)
        return self._render_html_to_png(html)

    def save_preview_to_mail(self, mail, png_bytes: bytes) -> None:
        """Upload PNG directly to MinIO and stamp (bucket, key) on the row.

        Bypasses Django's ImageField + DEFAULT_FILE_STORAGE entirely so the
        admin and API can never end up with a `/media/...` URL that the
        prod urlconf does not route. The MinIO key is keyed by Mail PK so
        previews stay unique per row; re-renders overwrite in place.
        """
        try:
            client = get_store()
        except Exception:
            logger.exception(
                "Mail preview upload skipped: object store not configured. "
                "mail_id=%s", mail.pk,
            )
            return

        bucket = getattr(settings, "MAIL_PREVIEW_BUCKET", _DEFAULT_PREVIEW_BUCKET)
        key = f"{mail.pk}.png"

        _ensure_bucket(client, bucket)

        try:
            client.put(
                bucket,
                key,
                io.BytesIO(png_bytes),
                length=len(png_bytes),
                content_type="image/png",
            )
        except Exception:
            logger.exception(
                "Failed to upload mail preview to MinIO bucket=%s key=%s "
                "mail_id=%s", bucket, key, mail.pk,
            )
            return

        mail.preview_bucket = bucket
        mail.preview_object_key = key
        mail.save(update_fields=["preview_bucket", "preview_object_key"])

    # Internals

    def _build_preview_html(self, msg: EmailMessage) -> str:
        """Wrap the parsed message in a minimal, safe HTML document.

        We escape every header value, prefer the HTML body when present,
        and fall back to the text/plain body wrapped in <pre>. The body
        HTML goes through sanitize_email_html() (allow-list, no resource
        references) and is rasterised by the isolated renderer with JavaScript
        off, every request aborted and no network route, so it cannot phone
        home, read host files, or execute script.
        """
        header_rows = []
        for name in _VISIBLE_HEADERS:
            value = msg.get(name, "").strip()
            if not value:
                continue
            header_rows.append(
                f'<tr style="{_KEEP_VISIBLE.format("table-row")}">'
                f'<th style="{_KEEP_VISIBLE.format("table-cell")}">{escape(name)}</th>'
                f'<td style="{_KEEP_VISIBLE.format("table-cell")}">{escape(value)}</td></tr>'
            )

        body_html = self._extract_body_html(msg)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<style>
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
                 "Helvetica Neue", Arial, sans-serif;
    color: #1f2937;
    background: #ffffff;
    margin: 24px;
    width: {_RENDER_WIDTH_PX - 48}px;
  }}
  table.headers {{
    border-collapse: collapse;
    width: 100%;
    margin-bottom: 18px;
    font-size: 13px;
  }}
  table.headers th {{
    text-align: left;
    vertical-align: top;
    color: #6b7280;
    font-weight: 600;
    padding: 4px 12px 4px 0;
    width: 90px;
    white-space: nowrap;
  }}
  table.headers td {{
    padding: 4px 0;
    word-break: break-word;
  }}
  hr.sep {{
    border: 0;
    border-top: 1px solid #e5e7eb;
    margin: 0 0 18px 0;
  }}
  div.body {{
    font-size: 14px;
    line-height: 1.45;
    word-break: break-word;
  }}
  div.body pre {{
    white-space: pre-wrap;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 12px;
  }}
  img {{ max-width: 100%; height: auto; }}
</style>
</head>
<body>
  <table class="headers">{''.join(header_rows) or '<tr><td>(no headers)</td></tr>'}</table>
  <hr class="sep">
  <div class="body">{body_html}</div>
</body>
</html>"""

    def _extract_body_html(self, msg: EmailMessage) -> str:
        """Return rendered body HTML.

        Order of preference: text/html part > text/plain part > literal
        "(empty body)" placeholder. text/plain is wrapped in <pre> and
        escaped so it survives intact.
        """
        try:
            html_part = msg.get_body(preferencelist=("html",))
        except Exception:
            html_part = None

        if html_part is not None:
            try:
                body = sanitize_email_html(html_part.get_content())
                if "<img src=" in body or nh3.clean(body, tags=set()).strip():
                    return body
                # Image-only / iframe-only / truncated to nothing: show the text part.
            except Exception:
                logger.exception("Failed to decode HTML body; falling back to text/plain")

        try:
            text_part = msg.get_body(preferencelist=("plain",))
        except Exception:
            text_part = None

        if text_part is not None:
            try:
                return f"<pre>{escape(text_part.get_content())}</pre>"
            except Exception:
                logger.exception("Failed to decode text/plain body")

        return "<em>(empty body)</em>"

    def _render_html_to_png(self, html: str) -> Optional[bytes]:
        # A session of our own with trust_env off: the renderer is an internal
        # service, so HTTP(S)_PROXY from the environment must not apply to it.
        with requests.Session() as session:
            session.trust_env = False
            try:
                resp = session.post(
                    f"{_RENDERER_URL}/render",
                    data=html.encode("utf-8"),
                    headers={"Content-Type": "text/html; charset=utf-8"},
                    timeout=_RENDER_TIMEOUT,
                )
            except requests.RequestException as exc:
                logger.error("mail renderer unreachable: %s", exc)
                return None

        if resp.status_code != 200:
            logger.error("mail renderer answered %s: %s", resp.status_code, resp.text[:200])
            return None

        png_bytes = resp.content
        if len(png_bytes) > _MAX_PNG_BYTES:
            logger.warning(
                "mail renderer returned %d bytes (limit %d), dropping instead of storing",
                len(png_bytes), _MAX_PNG_BYTES,
            )
            return None
        return png_bytes


# Object store helpers

def _ensure_bucket(store, bucket: str) -> None:
    """Create the preview bucket on first use; idempotent."""
    try:
        store.ensure_bucket(bucket)
    except Exception:
        logger.warning(
            "ensure_bucket(%s) failed (continuing, put will retry)",
            bucket, exc_info=True,
        )
