"""Fetch the urlscan.io scan screenshot referenced by an Urlscan.io_Scan
report_full. One GET to urlscan.io (never the target URL). None on any failure."""
from __future__ import annotations

import logging
from typing import Any, Optional
from urllib.parse import urlparse

import requests

from .lookyloo import _MAX_BYTES, _PNG_MAGIC

logger = logging.getLogger(__name__)

_TIMEOUT = 10


def _screenshot_url(report_full: Any) -> Optional[str]:
    if not isinstance(report_full, dict):
        return None
    for container in (report_full, report_full.get("results")):
        if not isinstance(container, dict):
            continue
        task = container.get("task")
        if isinstance(task, dict) and isinstance(task.get("screenshotURL"), str):
            return task["screenshotURL"]
        if isinstance(container.get("screenshot"), str):
            return container["screenshot"]
    return None


def _is_urlscan(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return host == "urlscan.io" or host.endswith(".urlscan.io")


def extract(report_full: Any, data_type: str, value: Optional[str]) -> Optional[bytes]:
    url = _screenshot_url(report_full)
    if not url or not url.startswith("https://") or not _is_urlscan(url):
        return None
    try:
        resp = requests.get(url, timeout=_TIMEOUT, stream=True)
        resp.raise_for_status()
        buf = b""
        for chunk in resp.iter_content(64 * 1024):
            buf += chunk
            if len(buf) > _MAX_BYTES:
                logger.warning("urlscan screenshot: oversized")
                return None
    except Exception as exc:  # noqa: BLE001 - network is best-effort
        logger.warning("urlscan screenshot fetch failed: %s", exc)
        return None
    return buf if buf.startswith(_PNG_MAGIC) else None
