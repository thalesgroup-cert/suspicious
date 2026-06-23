"""Dispatch-time planning for URL analysis.

Collapses equivalent URLs, reuses recent cross-case results, and caps
per-domain analysis volume to the most interesting URLs. See
docs/superpowers/specs/2026-06-23-url-analysis-planner-design.md.

Every helper here is intended to be safe and fail-open: callers must never
let a planning failure drop a URL from analysis.
"""
from __future__ import annotations

from urllib.parse import urlsplit, parse_qs


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
