"""Unwrap known link-wrappers (ATP SafeLinks, Proofpoint URLDefense) into the
real URL they hide, so the real target becomes its own observable and gets
analyzed. Pure — no network. Fail-open: any error yields ``[]``.
"""
from __future__ import annotations

import logging
from urllib.parse import parse_qs, unquote, urlsplit

logger = logging.getLogger(__name__)

_SAFELINKS_SUFFIX = ".safelinks.protection.outlook.com"
_URLDEFENSE_HOSTS = ("urldefense.com", "urldefense.proofpoint.com")


def _is_http_url(value: str) -> bool:
    try:
        parts = urlsplit(value)
        return parts.scheme in ("http", "https") and bool(parts.hostname)
    except ValueError:
        return False


def _safelinks(parts) -> list[str]:
    if not (parts.hostname or "").lower().endswith(_SAFELINKS_SUFFIX):
        return []
    target = parse_qs(parts.query).get("url", [None])[0]
    return [target] if target and _is_http_url(target) else []


def _urldefense(url: str, parts) -> list[str]:
    if (parts.hostname or "").lower() not in _URLDEFENSE_HOSTS:
        return []
    path = parts.path or ""
    target = None
    if path.startswith("/v3/__") and "__;" in url:
        # ponytail: literal form only; v3's `*`/`**` char-run de-defanging is
        # rare in real mail — add it if a sample turns up needing it.
        target = url.split("/v3/__", 1)[1].split("__;", 1)[0]
    elif path.startswith(("/v2/url", "/v1/url")):
        raw = parse_qs(parts.query).get("u", [None])[0]
        if raw is not None:
            if path.startswith("/v2/"):
                raw = raw.replace("-", "%").replace("_", "/")
            target = unquote(raw)
    return [target] if target and _is_http_url(target) else []


_MAX_DEPTH = 5


def _direct_hops(url: str) -> list[str]:
    try:
        parts = urlsplit(url)
        return _safelinks(parts) or _urldefense(url, parts)
    except Exception:  # noqa: BLE001 — observable creation must never break here
        logger.warning("unwrap_url: failed on %r; fail-open", url, exc_info=True)
        return []


def unwrap_url(url: str) -> list[str]:
    """Return the real URL(s) hidden inside known wrappers (SafeLinks,
    URLDefense), recursing through wrapper-in-wrapper up to ``_MAX_DEPTH``.
    ``[]`` if ``url`` is not a wrapper. Order: outermost hop first.
    """
    out: list[str] = []
    seen = {url}
    queue = list(_direct_hops(url))
    depth = 0
    while queue and depth < _MAX_DEPTH:
        depth += 1
        nxt: list[str] = []
        for hop in queue:
            if hop in seen:
                continue
            seen.add(hop)
            out.append(hop)
            nxt.extend(_direct_hops(hop))
        queue = nxt
    return out
