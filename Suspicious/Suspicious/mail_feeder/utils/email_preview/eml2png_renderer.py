"""
Render an .eml/.msg file to a PNG preview.

Replaces the previous external `eml2png==0.0.2` CLI dependency with a
pure-Python pipeline: stdlib `email` parses the message, we build a
sanitised HTML wrapper (headers + body), then `imgkit` calls the
already-installed `wkhtmltopdf` binary to rasterise to PNG.

`wkhtmltopdf` is staying in the runtime image for now; imgkit is a
thin Python wrapper around it.

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
import re
from email.message import EmailMessage
from email.policy import default as email_default_policy
from html import escape
from pathlib import Path
from typing import Optional

from django.conf import settings

logger = logging.getLogger(__name__)

_DEFAULT_PREVIEW_BUCKET = "mail-previews"


_RENDER_WIDTH_PX = 900

_VISIBLE_HEADERS = ("From", "To", "Cc", "Subject", "Date", "Reply-To")

_REMOTE_CSS_RE = re.compile(
    r"<link\b[^>]*>|@import\b[^;]*;", re.IGNORECASE | re.DOTALL
)

# imgkit's `no-images` option only blocks <img> tag loads — not CSS
# background-image/@font-face url(...) (in <style> blocks or inline
# style="" attributes) or other resource-fetching tags. Phishing HTML
# routinely hides tracking pixels in exactly those spots. The render
# worker has no route to arbitrary external hosts, so each such fetch
# blocks on connect until timeout instead of failing fast, and enough of
# them trip the Celery soft time limit.
_REMOTE_URL_FUNC_RE = re.compile(
    r"url\(\s*['\"]?https?://[^'\")]+['\"]?\s*\)", re.IGNORECASE
)
_REMOTE_SRC_ATTR_RE = re.compile(
    r'\b(?:src|data)\s*=\s*(["\'])https?://.*?\1', re.IGNORECASE
)


def _strip_remote_resources(html: str) -> str:
    html = _REMOTE_CSS_RE.sub("", html)
    html = _REMOTE_URL_FUNC_RE.sub("url()", html)
    html = _REMOTE_SRC_ATTR_RE.sub("", html)
    return html


class Eml2PngRenderer:
    """Render an .eml file to a PNG preview via stdlib email + imgkit."""

    def __init__(self) -> None:
        try:
            import imgkit  # noqa: F401  (probed for availability)
            self._imgkit_available = True
        except Exception:
            self._imgkit_available = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def render_eml_path_to_png_bytes(self, eml_path: Path) -> Optional[bytes]:
        if not self._imgkit_available:
            logger.error(
                "imgkit not importable — install imgkit and wkhtmltopdf "
                "in the runtime image to enable mail previews"
            )
            return None

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
        client = _build_minio_client()
        if client is None:
            logger.error(
                "Mail preview upload skipped: MinIO client not configured "
                "(settings.MINIO_STORAGE_* missing). mail_id=%s", mail.pk,
            )
            return

        bucket = getattr(settings, "MAIL_PREVIEW_BUCKET", _DEFAULT_PREVIEW_BUCKET)
        key = f"{mail.pk}.png"

        _ensure_bucket(client, bucket)

        try:
            client.put_object(
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

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _build_preview_html(self, msg: EmailMessage) -> str:
        """Wrap the parsed message in a minimal, safe HTML document.

        We escape every header value, prefer the HTML body when present,
        and fall back to the text/plain body wrapped in <pre>. The body
        HTML is rendered as-is but rasterised to a PNG with remote images,
        JavaScript and local-file access all disabled at imgkit time (see
        _render_html_to_png), and remote-fetching CSS/attributes stripped
        (see _strip_remote_resources) — so it cannot phone home, read host
        files, or execute script.
        """
        header_rows = []
        for name in _VISIBLE_HEADERS:
            value = msg.get(name, "").strip()
            if not value:
                continue
            header_rows.append(
                f"<tr><th>{escape(name)}</th><td>{escape(value)}</td></tr>"
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
                return _strip_remote_resources(html_part.get_content())
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
        import imgkit

        options = {
            "format": "png",
            "encoding": "utf-8",
            "width": str(_RENDER_WIDTH_PX),
            "quiet": "",
            "no-images": "",
            "disable-javascript": "",
            "disable-local-file-access": "",
        }

        try:
            return imgkit.from_string(html, output_path=False, options=options)
        except Exception as exc:
            logger.error("imgkit failed to render preview: %s", exc)
            return None


# ---------------------------------------------------------------------------
# MinIO helpers
# ---------------------------------------------------------------------------

def _build_minio_client():
    """Build the MinIO client used to store previews, or None on failure.

    Prefer the platform-wide client (`storage.s3` runtime config), so
    previews live in the same MinIO instance as every other object — the
    same source the rest of the backend and the preview *fetch* path use.
    Falls back to legacy django-minio-storage `MINIO_STORAGE_*` settings
    for older deployments that still configure storage that way.
    """
    try:
        from common.clients import get_s3_client
        client = get_s3_client()
        if client is not None:
            return client
    except Exception:
        logger.exception(
            "get_s3_client failed for previews; falling back to MINIO_STORAGE_*"
        )

    endpoint = getattr(settings, "MINIO_STORAGE_ENDPOINT", None)
    access_key = getattr(settings, "MINIO_STORAGE_ACCESS_KEY", None)
    secret_key = getattr(settings, "MINIO_STORAGE_SECRET_KEY", None)
    if not (endpoint and access_key and secret_key):
        return None

    try:
        from minio import Minio
        return Minio(
            endpoint=endpoint,
            access_key=access_key,
            secret_key=secret_key,
            secure=bool(getattr(settings, "MINIO_STORAGE_USE_HTTPS", False)),
        )
    except Exception:
        logger.exception("Failed to instantiate Minio client for previews")
        return None


def _ensure_bucket(client, bucket: str) -> None:
    """Create the preview bucket on first use; idempotent."""
    try:
        if not client.bucket_exists(bucket):
            client.make_bucket(bucket)
    except Exception:
        logger.warning(
            "ensure_bucket(%s) failed (continuing — put_object will retry)",
            bucket, exc_info=True,
        )
