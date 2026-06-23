"""Dispatch-time planning for URL analysis.

Collapses equivalent URLs, reuses recent cross-case results, and caps
per-domain analysis volume to the most interesting URLs. See
docs/superpowers/specs/2026-06-23-url-analysis-planner-design.md.

Every helper here is intended to be safe and fail-open: callers must never
let a planning failure drop a URL from analysis.
"""
from __future__ import annotations

import ipaddress
import logging
from urllib.parse import urlsplit, parse_qs

logger = logging.getLogger(__name__)


DEFAULT_SHORTENER_DOMAINS = (
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "is.gd", "cutt.ly", "rb.gy", "rebrand.ly", "lnkd.in",
)
DEFAULT_SUSPICIOUS_TLDS = (
    "zip", "mov", "xyz", "top", "click", "country", "kim", "work",
    "gq", "ml", "cf", "tk", "ga",
)
OPEN_REDIRECT_KEYS = frozenset({"url", "next", "redirect", "r", "dest", "continue", "return", "u"})
RISKY_PATH_SUFFIXES = (".exe", ".scr", ".js", ".hta", ".iso", ".zip", ".rar", ".7z", ".msi", ".bat", ".cmd")


def canonical_key(url: str) -> str:
    """Return the canonical equivalence key for ``url``.

    Key = ``scheme://host/path?<sorted query-key set>``:
      * host lower-cased, leading ``www.`` stripped
      * fragment dropped
      * query *values* dropped, query *key names* kept and sorted

    URLs that differ only in query values (victim id, tracking token) collapse
    to one key; a URL that introduces a *new* query key (e.g. ``redirect``)
    stays distinct on purpose.
    """
    if "://" not in url:
        url = "http://" + url
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    port = f":{parts.port}" if parts.port else ""
    path = parts.path or "/"
    query_keys = sorted(parse_qs(parts.query, keep_blank_values=True).keys())
    query = "?" + "&".join(query_keys) if query_keys else ""
    return f"{parts.scheme}://{host}{port}{path}{query}"


def _cfg_list(key: str, default: tuple[str, ...]) -> tuple[str, ...]:
    from settings.config import get_config
    value = get_config(key, None)
    if isinstance(value, (list, tuple)) and value:
        return tuple(str(v).lower() for v in value)
    return default


def _registered_domain_lower(host: str) -> str:
    """Registered domain via the shared tldextract cache; '' on failure."""
    try:
        from mail_feeder.mail_utils.meioc import tldcache
        return (tldcache(host).registered_domain or "").lower()
    except Exception:  # noqa: BLE001 — scoring must never raise
        return ""


def score_interestingness(url: str, *, sender_domain: str | None = None) -> int:
    """Additive, table-driven interestingness score, clamped to 0..255.

    Higher = analyze sooner. Tuned so genuinely-suspicious traits outrank
    benign tracking noise; a payload-bearing query (``?redirect=``) is boosted
    so it survives per-domain capping.
    """
    try:
        if "://" not in url:
            url = "http://" + url
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        path = (parts.path or "").lower()
        query_keys = {k.lower() for k in parse_qs(parts.query, keep_blank_values=True)}

        score = 0

        is_ip = False
        try:
            ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            pass
        if is_ip:
            score += 40

        if "xn--" in host:
            score += 30

        shorteners = _cfg_list("url_analysis.shortener_domains", DEFAULT_SHORTENER_DOMAINS)
        if any(host == s or host.endswith("." + s) for s in shorteners):
            score += 30

        if "@" in (parts.netloc or ""):
            score += 25

        if query_keys & OPEN_REDIRECT_KEYS:
            score += 25

        sus_tlds = _cfg_list("url_analysis.suspicious_tlds", DEFAULT_SUSPICIOUS_TLDS)
        if not is_ip and host.rsplit(".", 1)[-1] in sus_tlds:
            score += 20

        if any(path.endswith(suf) for suf in RISKY_PATH_SUFFIXES):
            score += 20

        if parts.port and parts.port not in (80, 443):
            score += 15

        depth = len([seg for seg in path.split("/") if seg])
        if depth >= 4 or len(path) > 60:
            score += 10

        if len(query_keys) > 4:
            score += 5

        if sender_domain and not is_ip:
            if _registered_domain_lower(host) == sender_domain.lower():
                score -= 20

        if depth == 0 and not query_keys:
            score -= 10

        return max(0, min(255, score))
    except Exception:  # noqa: BLE001 — scoring must never raise
        logger.warning("score_interestingness failed for %r; defaulting to 0", url, exc_info=True)
        return 0
