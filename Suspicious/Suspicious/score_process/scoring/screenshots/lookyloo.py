"""Extract the page screenshot from a Lookyloo_Screenshot report_full.
Pure dict -> bytes; no ORM, no network. None when there is no usable PNG."""
from __future__ import annotations

import base64
import binascii
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

_MAX_BYTES = 8 * 1024 * 1024
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_KEYS = ("screenshot", "raw")


def _b64_field(report_full: Any) -> Optional[str]:
    if not isinstance(report_full, dict):
        return None
    for container in (report_full, report_full.get("results")):
        if isinstance(container, dict):
            for k in _KEYS:
                v = container.get(k)
                if isinstance(v, str) and v:
                    return v
    return None


def extract(report_full: Any, data_type: str, value: Optional[str]) -> Optional[bytes]:
    b64 = _b64_field(report_full)
    if not b64:
        return None
    try:
        raw = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        logger.warning("lookyloo screenshot: bad base64")
        return None
    if len(raw) > _MAX_BYTES or not raw.startswith(_PNG_MAGIC):
        logger.warning("lookyloo screenshot: oversized or not a PNG (%d bytes)", len(raw))
        return None
    return raw
