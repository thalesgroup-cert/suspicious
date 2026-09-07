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


def _blocked(value: str, data_type: str) -> str:
    """Non-empty reason if `value` must not become a live observable."""
    if data_type == "url":
        from api.serializers.submit import _check_no_ssrf_ip
        try:
            _check_no_ssrf_ip(value)
        except ValueError as exc:
            return str(exc) or "SSRF-blocked target"
    if data_type in ("url", "domain"):
        from score_process.scoring.cortex_analyzers.allow_list import check_allow_list
        try:
            allow = check_allow_list(value, data_type)
            for reason in allow.model_dump().values():
                if reason:
                    return f"allow-listed ({reason})"
        except Exception:  # noqa: BLE001 — never block ingestion on an allow-list error
            logger.warning("derived: allow-list check failed for %r", value, exc_info=True)
    return ""


EXTRACTORS: dict[str, Callable[[Any], list[tuple[str, str]]]] = {
    "UnshortenLink_1_2": _unshorten,
    "QrDecode_1_0": _qrdecode,
}
