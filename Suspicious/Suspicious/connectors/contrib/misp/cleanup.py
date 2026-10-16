"""
Find company-linked attributes already sitting in a MISP event.

The push filters (see internal.py) only stop new leaks; objects pushed before
them stay in the shared event. scan_event() lists what the filters would have
kept out, so it can be reviewed and removed.
"""
from __future__ import annotations
from dataclasses import dataclass

from .internal import (
    company_addresses,
    external_addresses,
    is_company_domain,
    url_host,
)

_ADDRESS_TYPES = frozenset({"email", "email-src", "email-dst", "email-reply-to"})
_DOMAIN_TYPES = frozenset({"domain", "hostname"})
_URL_TYPES = frozenset({"url", "uri", "link"})
_RECIPIENT_NAME = "email-dst-display-name"
# Objects removed as a whole when their indicator is on a company domain.
_WHOLE_OBJECTS = frozenset({"domain-ip", "url"})


@dataclass(frozen=True)
class Finding:
    kind: str        # "attribute" | "object"
    id: str
    type: str        # MISP attribute type, or object name for kind "object"
    value: str
    reason: str
    keep: str = ""   # attribute only: the external addresses to leave in place

    @property
    def action(self) -> str:
        return "rewrite" if self.keep else "delete"


def _attribute_reason(attr: dict, domains) -> tuple[str, str] | None:
    """(reason, value to keep) when the attribute is company-linked."""
    kind, value = attr.get("type") or "", attr.get("value") or ""
    if kind in _ADDRESS_TYPES:
        if company_addresses(value, domains):
            return "company address", external_addresses(value, domains)
    elif kind == _RECIPIENT_NAME:
        return "recipient display name", ""
    elif kind in _DOMAIN_TYPES:
        if is_company_domain(value, domains):
            return "company domain", ""
    elif kind == "domain|ip":
        if is_company_domain(value.split("|", 1)[0], domains):
            return "company domain", ""
    elif kind in _URL_TYPES:
        if is_company_domain(url_host(value), domains):
            return "company url", ""
    return None


def _scan_attributes(attrs, domains) -> list[tuple[dict, str, str]]:
    found = []
    for attr in attrs or []:
        if attr.get("deleted"):
            continue
        hit = _attribute_reason(attr, domains)
        if hit:
            found.append((attr, *hit))
    return found


def _as_finding(attr: dict, reason: str, keep: str) -> Finding:
    return Finding("attribute", str(attr["id"]), attr.get("type") or "",
                   attr.get("value") or "", reason, keep)


def scan_event(event: dict, domains) -> list[Finding]:
    """Company-linked attributes and objects of a MISP event (the "Event" dict)."""
    findings = [_as_finding(*hit) for hit in _scan_attributes(event.get("Attribute"), domains)]

    for obj in event.get("Object") or []:
        if obj.get("deleted"):
            continue
        hits = _scan_attributes(obj.get("Attribute"), domains)
        if not hits:
            continue
        if obj.get("name") in _WHOLE_OBJECTS:
            first_attr, reason, _ = hits[0]
            findings.append(Finding("object", str(obj["id"]), obj["name"],
                                    first_attr.get("value") or "", reason))
            continue
        findings.extend(_as_finding(*hit) for hit in hits)
        if obj.get("name") == "email" and any(
            a.get("object_relation") == "from" and not keep for a, _, keep in hits
        ):
            flagged = {a["id"] for a, _, _ in hits}
            for attr in obj.get("Attribute") or []:
                if (attr.get("object_relation") == "from-display-name"
                        and not attr.get("deleted") and attr["id"] not in flagged):
                    findings.append(_as_finding(attr, "display name of a company sender", ""))
    return findings
