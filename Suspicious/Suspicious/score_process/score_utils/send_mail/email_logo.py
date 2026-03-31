# mail_service/email_logo.py
"""
Normalises logo values from settings.json into a dict the Jinja2
templates can use without any logic inside the template.

settings.json values can be:
  - Full data URI:  "data:image/svg+xml;base64,PHN2Zy..."
                    "data:image/png;base64,iVBORw0..."
  - Raw base64:     "PHN2Zyb..."  (auto-detected by SVG magic bytes)
  - URL:            "https://example.com/logo.png"
  - File path:      "/app/static/logo.svg"
  - None / empty

Returns a dict:
  {
    "src":       full src= value ready for <img src="{{ logo.src }}">
    "mime":      "image/svg+xml" | "image/png" | "image/jpeg" | ""
    "is_svg":    True/False  — lets template choose rendering strategy
    "is_image":  True/False  — False when value is empty/None
  }

SVG notes
─────────
• Inline <svg> is stripped by Gmail and Outlook — always use <img>.
• data:image/svg+xml;base64,... works in Apple Mail, Outlook 365 web,
  Thunderbird, and most modern clients.
• Outlook 2007-2019 (desktop/MSO) does NOT render SVG at all.
  The template wraps the SVG <img> in a <!--[if !mso]> conditional
  and shows a plain text wordmark fallback for MSO clients.
"""

from __future__ import annotations
import base64
import re


_SVG_DATA_PREFIX  = "data:image/svg+xml;base64,"
_PNG_DATA_PREFIX  = "data:image/png;base64,"
_JPEG_DATA_PREFIX = "data:image/jpeg;base64,"
_GIF_DATA_PREFIX  = "data:image/gif;base64,"
_WEBP_DATA_PREFIX = "data:image/webp;base64,"

_DATA_PREFIXES = {
    _SVG_DATA_PREFIX:  "image/svg+xml",
    _PNG_DATA_PREFIX:  "image/png",
    _JPEG_DATA_PREFIX: "image/jpeg",
    _GIF_DATA_PREFIX:  "image/gif",
    _WEBP_DATA_PREFIX: "image/webp",
}

# SVG magic: raw base64 of "<svg" is "PHN2Zy" or "PHN2Zy..." (case-sensitive)
_SVG_B64_MAGIC = ("PHN2Zy", "Cjxzdmc", "77u/PHN2Z")  # <?xml ... or BOM variants


def _sniff_raw_base64(value: str) -> str:
    """Try to detect mime type from raw base64 string."""
    # SVG heuristic
    if any(value.startswith(m) for m in _SVG_B64_MAGIC):
        return "image/svg+xml"
    # PNG magic bytes: base64("PNG") = "iVBOR"
    if value.startswith("iVBOR"):
        return "image/png"
    # JPEG magic bytes: base64("ÿØÿ") = "/9j/"
    if value.startswith("/9j/"):
        return "image/jpeg"
    # GIF: base64("GIF8") = "R0lG"
    if value.startswith("R0lG"):
        return "image/gif"
    return ""


def resolve_logo(raw: str | None) -> dict:
    """
    Return a normalised logo descriptor dict from any logo value.

    Template usage:
        {% if logo.is_image %}
          <!--[if !mso]><!-->
          <img src="{{ logo.src }}" ...>
          <!--<![endif]-->
          <!--[if mso]>
          <span ...>{{ company_name }}</span>
          <![endif]-->
        {% endif %}
    """
    empty = {"src": "", "mime": "", "is_svg": False, "is_image": False}

    if not raw or not isinstance(raw, str):
        return empty

    raw = raw.strip()
    if not raw:
        return empty

    # ── Already a full data URI ──────────────────────────────────────────
    for prefix, mime in _DATA_PREFIXES.items():
        if raw.startswith(prefix):
            return {
                "src":      raw,
                "mime":     mime,
                "is_svg":   mime == "image/svg+xml",
                "is_image": True,
            }

    # ── URL or file path — pass through unchanged ────────────────────────
    if raw.startswith("http://") or raw.startswith("https://") or raw.startswith("/"):
        # Guess mime from extension
        lower = raw.lower()
        if lower.endswith(".svg"):
            mime = "image/svg+xml"
        elif lower.endswith(".png"):
            mime = "image/png"
        elif lower.endswith((".jpg", ".jpeg")):
            mime = "image/jpeg"
        else:
            mime = ""
        return {
            "src":      raw,
            "mime":     mime,
            "is_svg":   mime == "image/svg+xml",
            "is_image": True,
        }

    # ── Raw base64 — detect and wrap in data URI ─────────────────────────
    # Strip whitespace/newlines that sometimes appear in pasted base64
    b64 = re.sub(r"\s+", "", raw)
    mime = _sniff_raw_base64(b64)
    if mime:
        return {
            "src":      f"data:{mime};base64,{b64}",
            "mime":     mime,
            "is_svg":   mime == "image/svg+xml",
            "is_image": True,
        }

    # Unknown — still try to use it as-is (might be a URL fragment)
    return {
        "src":      raw,
        "mime":     "",
        "is_svg":   False,
        "is_image": bool(raw),
    }