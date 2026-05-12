"""
Render an .eml/.msg file to a PNG preview.

Replaces the previous external `eml2png==0.0.2` CLI dependency with a
pure-Python pipeline: stdlib `email` parses the message, we build a
sanitised HTML wrapper (headers + body), then `imgkit` calls the
already-installed `wkhtmltopdf` binary to rasterise to PNG.

`wkhtmltopdf` is staying in the runtime image for now; imgkit is a
thin Python wrapper around it.
"""
from __future__ import annotations

import email
import logging
from email.message import EmailMessage
from email.policy import default as email_default_policy
from html import escape
from pathlib import Path
from typing import Optional

from django.core.files.base import ContentFile

logger = logging.getLogger(__name__)


# Pixel-perfect width matches the eml-thumbnail use case in
# SubmissionsPage; investigation page scales up with CSS object-fit.
_RENDER_WIDTH_PX = 900

# Headers we surface in the preview. Anything else is dropped so the
# image stays compact and free of long Received-chains.
_VISIBLE_HEADERS = ("From", "To", "Cc", "Subject", "Date", "Reply-To")


class Eml2PngRenderer:
    """Render an .eml file to a PNG preview via stdlib email + imgkit."""

    def __init__(self) -> None:
        # Imported lazily so the module still loads when wkhtmltopdf is
        # missing (e.g. unit tests outside the Docker image). Failures
        # surface in render_eml_path_to_png_bytes with a clear log line.
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
        """Storage-aware: writes via DEFAULT_FILE_STORAGE (local/MinIO/dual).

        The filename includes the Mail PK so each preview lives at a unique
        key. The previous literal "preview.png" collided on MinIO (no
        get_available_name() rename) and every mail overwrote the same
        blob — `/media/mail_previews/preview.png` returning the wrong
        case's image (or 404'ing once a deploy wiped the volume).
        """
        mail.preview_png.save(
            f"preview_{mail.pk}.png", ContentFile(png_bytes), save=False
        )
        mail.save(update_fields=["preview_png"])

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _build_preview_html(self, msg: EmailMessage) -> str:
        """Wrap the parsed message in a minimal, safe HTML document.

        We escape every header value, prefer the HTML body when present,
        and fall back to the text/plain body wrapped in <pre>. Remote
        resources are blocked at imgkit time via --disable-external-links
        / --no-images flags to keep rendering offline and fast.
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
                return html_part.get_content()
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

        # Flags supported by wkhtmltoimage 0.12.6. The wkhtmltopdf-only
        # options (--disable-external-links etc.) are intentionally
        # absent — they make wkhtmltoimage exit 1.
        options = {
            "format": "png",
            "encoding": "utf-8",
            "width": str(_RENDER_WIDTH_PX),
            "quiet": "",
            # Block remote fetches + local-FS reads + script execution.
            # Previews must be deterministic and must not phone home to
            # attacker-controlled hosts.
            "no-images": "",
            "disable-javascript": "",
            "disable-local-file-access": "",
        }

        try:
            return imgkit.from_string(html, output_path=False, options=options)
        except Exception as exc:
            logger.error("imgkit failed to render preview: %s", exc)
            return None
