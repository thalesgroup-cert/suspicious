# mail_service/email_logo.py
"""
Normalises logo values from settings.json into a dict the Jinja2
templates can use without any logic inside the template.

settings.json values can be:
  - Full data URI:  "data:image/svg+xml;base64,PHN2Zy..."
                    "data:image/png;base64,iVBORw0..."
  - Raw base64:     "PHN2Zy..."  (auto-detected by SVG magic bytes)
  - URL:            "https://example.com/logo.png"
  - File path:      "/app/static/logo.svg"
  - None / empty

Returns a dict:
  {
    "src":         full src= value ready for <img src="{{ logo.src }}">
    "mime":        "image/svg+xml" | "image/png" | "image/jpeg" | ""
    "is_svg":      True/False
    "is_data_uri": True/False  — Outlook blocks data: URIs
    "is_url":      True/False  — safe for Outlook <img>
    "is_image":    True/False  — False when value is empty/None
    "outlook_src": PNG data URI for use inside <!--[if mso]--> blocks,
                   or "" when conversion is unavailable/not applicable.
  }

Outlook PNG fallback
─────────────────────
Outlook 2007-2019 (MSO/Word rendering engine) blocks ALL data: URI images
and cannot render SVG at all.  When the logo is an SVG (either a data URI
or a raw base64 blob), resolve_logo() now:

  1. Extracts the raw SVG bytes.
  2. Converts them to PNG via cairosvg at the configured width (default 260 px).
  3. Caches the result in an in-process LRU cache keyed on a blake2b digest
     of the raw SVG bytes — so repeated calls for the same logo are free.
  4. Returns the PNG as a "data:image/png;base64,..." string in the
     `outlook_src` field.

The acknowledgement_email.jinja2 template (and any other email template)
uses this field inside the <!--[if mso]> conditional instead of the
plain-text wordmark fallback that was used previously:

    <!--[if mso]>
    <img src="{{ company_logo.outlook_src }}" ...>
    <![endif]-->

If cairosvg is not installed, or conversion fails for any reason,
`outlook_src` falls back to "" and the template can degrade gracefully
to the text wordmark.

Dependencies
────────────
  pip install cairosvg          # Requires libcairo2 (system package)
  apt-get install libcairo2     # Debian/Ubuntu
  brew install cairo            # macOS

Conversion is skipped (outlook_src="") when:
  - The logo is NOT an SVG
  - cairosvg is not importable
  - The SVG bytes cannot be decoded
  - cairosvg raises any exception during conversion
"""

from __future__ import annotations

import base64
import functools
import hashlib
import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)

# ── MIME prefix table ─────────────────────────────────────────────────────────
_DATA_PREFIXES: dict[str, str] = {
    "data:image/svg+xml;base64,": "image/svg+xml",
    "data:image/png;base64,":     "image/png",
    "data:image/jpeg;base64,":    "image/jpeg",
    "data:image/gif;base64,":     "image/gif",
    "data:image/webp;base64,":    "image/webp",
}

# SVG magic bytes in base64 (covers <?xml …>, <svg…>, and BOM variants)
_SVG_B64_MAGIC = ("PHN2Zy", "Cjxzdmc", "77u/PHN2Z")

# Default output width for the Outlook PNG raster (px)
_OUTLOOK_PNG_WIDTH = 260


# ── cairosvg import (optional dependency) ─────────────────────────────────────

def _try_import_cairosvg():
    try:
        import cairosvg
        return cairosvg
    except ImportError:
        logger.warning(
            "cairosvg is not installed — SVG→PNG conversion for Outlook is disabled. "
            "Install with: pip install cairosvg"
        )
        return None


_cairosvg = _try_import_cairosvg()


# ── Cached SVG → PNG converter ────────────────────────────────────────────────

@functools.lru_cache(maxsize=64)
def _svg_bytes_to_png_data_uri(svg_bytes: bytes, width: int) -> str:
    """
    Convert raw SVG bytes to a PNG data URI, cached by content hash + width.

    The LRU cache uses the raw bytes as the key — identical SVG content
    is only converted once per process lifetime regardless of how many
    emails are rendered.

    Returns "" on any failure so callers always get a safe fallback.
    """
    if _cairosvg is None:
        return ""
    try:
        png_bytes = _cairosvg.svg2png(bytestring=svg_bytes, output_width=width)
        b64       = base64.b64encode(png_bytes).decode("ascii")
        return "data:image/png;base64," + b64
    except Exception as exc:
        logger.warning("SVG→PNG conversion failed: %s", exc)
        return ""


def _extract_svg_bytes(raw_b64: str, prefix: str) -> Optional[bytes]:
    """
    Decode the base64 payload of a data URI or raw base64 string into bytes.

    Returns None if decoding fails.
    """
    b64_payload = raw_b64[len(prefix):] if prefix else raw_b64
    b64_clean   = re.sub(r"\s+", "", b64_payload)
    try:
        return base64.b64decode(b64_clean)
    except Exception as exc:
        logger.debug("base64 decode failed for SVG payload: %s", exc)
        return None


def _make_outlook_src(raw: str, prefix: str, width: int = _OUTLOOK_PNG_WIDTH) -> str:
    """
    Given the raw SVG data URI string and its matched prefix, return the
    Outlook-safe PNG data URI (or "" on failure).
    """
    svg_bytes = _extract_svg_bytes(raw, prefix)
    if svg_bytes is None:
        return ""
    return _svg_bytes_to_png_data_uri(svg_bytes, width)


# ── Raw base64 type sniffer ───────────────────────────────────────────────────

def _sniff_raw_base64(value: str) -> str:
    """Return MIME type detected from raw base64 magic bytes, or ""."""
    if any(value.startswith(m) for m in _SVG_B64_MAGIC):
        return "image/svg+xml"
    if value.startswith("iVBOR"):
        return "image/png"
    if value.startswith("/9j/"):
        return "image/jpeg"
    if value.startswith("R0lG"):
        return "image/gif"
    return ""


# ── Public API ────────────────────────────────────────────────────────────────

def resolve_logo(raw: str | None, outlook_png_width: int = _OUTLOOK_PNG_WIDTH) -> dict:
    """
    Return a normalised logo descriptor dict from any logo value.

    Fields
    ──────
    src          — ready-to-use src= value for non-Outlook clients
    mime         — detected MIME type string
    is_svg       — True when mime == image/svg+xml
    is_data_uri  — True when src starts with "data:"
    is_url       — True when src is an http(s) URL
    is_image     — True when any image content is present
    outlook_src  — PNG data URI for <!--[if mso]--> blocks; "" when N/A

    Template usage
    ──────────────
    {% if company_logo.is_image %}
      {% if company_logo.is_data_uri or company_logo.is_svg %}
        <!--[if !mso]><!-->
        <img src="{{ company_logo.src }}" ...>
        <!--<![endif]-->
        <!--[if mso]>
        {% if company_logo.outlook_src %}
        <img src="{{ company_logo.outlook_src }}" ...>
        {% else %}
        <span ...>{{ company_name }}</span>
        {% endif %}
        <![endif]-->
      {% else %}
        <img src="{{ company_logo.src }}" ...>
      {% endif %}
    {% endif %}
    """
    empty: dict = {
        "src":         "",
        "mime":        "",
        "is_svg":      False,
        "is_data_uri": False,
        "is_url":      False,
        "is_image":    False,
        "outlook_src": "",
    }

    if not raw or not isinstance(raw, str):
        return empty

    raw = raw.strip()
    if not raw:
        return empty

    # ── Already a full data URI ───────────────────────────────────────────
    for prefix, mime in _DATA_PREFIXES.items():
        if raw.startswith(prefix):
            is_svg      = mime == "image/svg+xml"
            outlook_src = _make_outlook_src(raw, prefix, outlook_png_width) if is_svg else ""
            return {
                "src":         raw,
                "mime":        mime,
                "is_svg":      is_svg,
                "is_data_uri": True,
                "is_url":      False,
                "is_image":    True,
                "outlook_src": outlook_src,
            }

    # ── URL or absolute file path — pass through unchanged ────────────────
    if raw.startswith("http://") or raw.startswith("https://") or raw.startswith("/"):
        lower = raw.lower()
        mime  = (
            "image/svg+xml" if lower.endswith(".svg")
            else "image/png"  if lower.endswith(".png")
            else "image/jpeg" if lower.endswith((".jpg", ".jpeg"))
            else ""
        )
        # Remote SVG URLs: we cannot fetch and convert at render time —
        # outlook_src is left as "" so the text wordmark fallback is used.
        return {
            "src":         raw,
            "mime":        mime,
            "is_svg":      mime == "image/svg+xml",
            "is_data_uri": False,
            "is_url":      raw.startswith("http://") or raw.startswith("https://"),
            "is_image":    True,
            "outlook_src": "",
        }

    # ── Raw base64 — detect, wrap in data URI, and convert if SVG ─────────
    b64  = re.sub(r"\s+", "", raw)
    mime = _sniff_raw_base64(b64)
    if mime:
        src         = "data:%s;base64,%s" % (mime, b64)
        is_svg      = mime == "image/svg+xml"
        # For a raw base64 SVG the prefix is "" — pass the raw b64 directly
        outlook_src = _svg_bytes_to_png_data_uri(
            _extract_svg_bytes(b64, "") or b"", outlook_png_width
        ) if is_svg else ""
        return {
            "src":         src,
            "mime":        mime,
            "is_svg":      is_svg,
            "is_data_uri": True,
            "is_url":      False,
            "is_image":    True,
            "outlook_src": outlook_src,
        }

    # Unknown — pass through as-is, no Outlook conversion
    return {
        "src":         raw,
        "mime":        "",
        "is_svg":      False,
        "is_data_uri": raw.startswith("data:"),
        "is_url":      raw.startswith("http"),
        "is_image":    bool(raw),
        "outlook_src": "",
    }