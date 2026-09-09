"""Parse a free-text blob of indicators into typed, deduped entries.
Reuses Suspicious's existing per-type validators — no new detection logic."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

_SPLIT = re.compile(r"[\s,;]+")
_HASH = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
# Same pattern as the frontend preview (parseIndicators.ts) so the count the
# analyst sees matches what the server accepts. Rejects user@host, host:port,
# and all-numeric strings.
_DOMAIN = re.compile(r"^[a-z0-9.-]+\.[a-z]{2,}$", re.IGNORECASE)


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
    if "/" not in value and _DOMAIN.match(value):
        return "domain"
    return None


def expand_wrappers(indicators: list[ParsedIndicator]) -> list[ParsedIndicator]:
    """Append the real URL(s) hidden inside any link-wrapper indicator
    (ATP SafeLinks, Proofpoint URLDefense). The wrapper indicator is kept."""
    from url_process.url_utils.url_unwrap import unwrap_url

    seen = {i.value.lower() for i in indicators}
    out = list(indicators)
    for ind in indicators:
        if ind.type != "url":
            continue
        for target in unwrap_url(ind.value):
            if target.lower() in seen:
                continue
            seen.add(target.lower())
            out.append(ParsedIndicator(raw=ind.raw, value=target, type="url"))
    return out


def _json_strings(node) -> list[str]:
    if isinstance(node, str):
        return [node]
    if isinstance(node, dict):
        return [s for v in node.values() for s in _json_strings(v)]
    if isinstance(node, list):
        return [s for v in node for s in _json_strings(v)]
    return []


def indicators_from_file(name: str, raw: bytes) -> list["ParsedIndicator"]:
    """Extract indicators from an uploaded IOC-list file (.txt / .csv / .json).

    JSON is flattened to its string leaves; .txt/.csv fall straight through
    parse_indicators (its splitter already handles newlines, commas and
    semicolons). No new detection logic — parse_indicators does refang + type.
    """
    text = raw.decode("utf-8", "replace")
    if name.lower().endswith(".json"):
        import json
        try:
            text = "\n".join(_json_strings(json.loads(text)))
        except ValueError:
            pass  # not valid JSON — treat as plain text
    return parse_indicators(text)


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
