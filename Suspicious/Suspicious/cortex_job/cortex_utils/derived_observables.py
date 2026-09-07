"""Turn an extractor analyzer's report into new observables in the same case.
See docs/specs/2026-09-07-derived-observables-design.md.
"""
from __future__ import annotations

import logging
from typing import Any, Callable

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")

_OBSERVABLE_TYPES = {"url", "domain", "ip", "hash", "mail"}


def _unshorten(full: Any) -> list[tuple[str, str]]:
    if not isinstance(full, dict) or not full.get("found"):
        return []
    url = full.get("url")
    return [(url, "url")] if isinstance(url, str) and url else []


def _qrdecode(full: Any) -> list[tuple[str, str]]:
    if not isinstance(full, dict):
        return []
    out: list[tuple[str, str]] = []
    for entry in full.get("results_list") or []:
        res = entry.get("results") if isinstance(entry, dict) else None
        if not isinstance(res, dict):
            continue
        value, dtype = res.get("data"), str(res.get("data_type") or "").lower()
        if isinstance(value, str) and value and dtype in _OBSERVABLE_TYPES:
            out.append((value, dtype))
    return out


EXTRACTORS: dict[str, Callable[[Any], list[tuple[str, str]]]] = {
    "UnshortenLink_1_2": _unshorten,
    "QrDecode_1_0": _qrdecode,
}
