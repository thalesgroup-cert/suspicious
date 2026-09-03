"""Parse a free-text blob of indicators into typed, deduped entries.
Reuses Suspicious's existing per-type validators — no new detection logic."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

_SPLIT = re.compile(r"[\s,;]+")
_HASH = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")


def _refang(s: str) -> str:
    return (s.replace("hxxp://", "http://").replace("hxxps://", "https://")
             .replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
             .replace("[dot]", ".").strip().strip("<>\"'"))


@dataclass
class ParsedIndicator:
    raw: str
    value: str
    type: Optional[str]


def _classify(value: str) -> Optional[str]:
    from ip_process.ip_utils.ip_handler import IPHandler

    if _HASH.match(value):
        return "hash"
    try:
        if IPHandler().validate_ip(value):
            return "ip"
    except Exception:
        pass
    if value.startswith(("http://", "https://")):
        return "url"
    if "." in value and " " not in value and "/" not in value:
        return "domain"
    return None


def parse_indicators(text: str) -> list[ParsedIndicator]:
    seen: set[str] = set()
    out: list[ParsedIndicator] = []
    for token in _SPLIT.split(text or ""):
        if not token:
            continue
        value = _refang(token)
        if not value or value.lower() in seen:
            continue
        seen.add(value.lower())
        out.append(ParsedIndicator(raw=token, value=value, type=_classify(value)))
    return out
