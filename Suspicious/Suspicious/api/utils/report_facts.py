"""Plain facts for the case report, extracted defensively from analyzer payloads.

Pure dict -> dataclass; no ORM, no network. Payload keys may be missing, null or
of the wrong type: every reader goes through get_path and isinstance checks."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from score_process.scoring.enrichment.virustotal import _attributes, _iso, _vt_link

_ISO_FMT = "%Y-%m-%dT%H:%M:%SZ"
_CAT_ORDER = {"malicious": 0, "suspicious": 1}


def get_path(obj: Any, *keys: str | int, default=None) -> Any:
    """Walk dicts and lists; default on a missing key, wrong container or bad index."""
    for key in keys:
        if isinstance(key, int) and not isinstance(key, bool):
            if not isinstance(obj, list) or not -len(obj) <= key < len(obj):
                return default
        elif not isinstance(obj, dict) or key not in obj:
            return default
        obj = obj[key]
    return obj


def iso_utc(value: Any) -> str | None:
    """Unix seconds, datetime or ISO string to %Y-%m-%dT%H:%M:%SZ; else None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return _iso(value)
    if isinstance(value, str):
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            value = datetime.fromisoformat(text)
        except ValueError:
            return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).strftime(_ISO_FMT)
    return None


@dataclass
class IndicatorFacts:
    detections: tuple[int, int, int] | None = None
    flagged_vendors: list[tuple[str, str | None]] = field(default_factory=list)
    reputation: int | None = None
    tags: list[str] = field(default_factory=list)
    total_votes: dict[str, int] = field(default_factory=dict)
    threat_severity: str | None = None
    country: str | None = None
    continent: str | None = None
    as_owner: str | None = None
    network: str | None = None
    rir: str | None = None
    asn: int | None = None
    resolved_ips: list[str] = field(default_factory=list)
    registrar: str | None = None
    created: str | None = None
    updated: str | None = None
    expires: str | None = None
    registrant: str | None = None
    contact_emails: list[str] = field(default_factory=list)
    contact_phones: list[str] = field(default_factory=list)
    name_servers: list[str] = field(default_factory=list)
    statuses: list[str] = field(default_factory=list)
    categories: dict[str, str] = field(default_factory=dict)
    popularity_ranks: dict[str, int] = field(default_factory=dict)
    final_url: str | None = None
    title: str | None = None
    http_code: int | None = None
    brands: list[str] = field(default_factory=list)
    threat_names: list[str] = field(default_factory=list)
    first_submission: str | None = None
    last_submission: str | None = None
    last_analysis: str | None = None
    times_submitted: int | None = None
    outgoing_links: int | None = None
    meaningful_name: str | None = None
    type_description: str | None = None
    md5: str | None = None
    sha1: str | None = None
    sha256: str | None = None
    threat_label: str | None = None
    names: list[str] = field(default_factory=list)
    size: int | None = None
    sandbox_verdicts: list[tuple[str, str]] = field(default_factory=list)
    vt_link: str | None = None


def _str(v: Any) -> str | None:
    return v.strip() or None if isinstance(v, str) else None


def _int(v: Any) -> int | None:
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _first(*vals):
    return next((v for v in vals if v is not None), None)


def _strs(v: Any) -> list[str]:
    """Non-empty strings of a list, order kept, duplicates dropped."""
    if not isinstance(v, list):
        return []
    return list(dict.fromkeys(s for s in map(_str, v) if s))


def _str_map(v: Any) -> dict[str, str]:
    if not isinstance(v, dict):
        return {}
    return {str(k): s for k, x in v.items() if (s := _str(x))}


def _whois(text: Any, label: str) -> str | None:
    if not isinstance(text, str):
        return None
    m = re.search(rf"^\s*{re.escape(label)}:[ \t]*(.+?)\s*$", text, re.M | re.I)
    return m.group(1) if m else None


def _vcard(entity: Any, name: str) -> list[str]:
    out: list[str] = []
    for item in get_path(entity, "vcard_array", default=None) or []:
        if get_path(item, "name") == name:
            out += _strs(get_path(item, "values"))
    return out


def _vendors(enrichment: dict, attrs: dict) -> list[tuple[str, str | None]]:
    rows = []
    vendors = enrichment.get("vendors")
    if isinstance(vendors, list):
        rows = [(get_path(v, "name"), get_path(v, "category"), get_path(v, "result")) for v in vendors]
    else:
        results = attrs.get("last_analysis_results")
        if isinstance(results, dict):
            rows = [(k, get_path(r, "category"), get_path(r, "result")) for k, r in results.items()]
    flagged = [(str(n), c, _str(r)) for n, c, r in rows if isinstance(n, str) and c in _CAT_ORDER]
    flagged.sort(key=lambda t: (_CAT_ORDER[t[1]], t[0].lower()))
    return [(n, r) for n, _, r in flagged]


def _detections(enrichment: dict, attrs: dict) -> tuple[int, int, int] | None:
    mal, total = _int(enrichment.get("malicious_count")), _int(enrichment.get("total"))
    if mal is not None and total is not None:
        return mal, _int(enrichment.get("suspicious_count")) or 0, total
    stats = attrs.get("last_analysis_stats")
    if isinstance(stats, dict) and stats:
        counts = [_int(v) or 0 for v in stats.values()]
        return _int(stats.get("malicious")) or 0, _int(stats.get("suspicious")) or 0, sum(counts)
    return None


def vt_facts(enrichment: dict | None, report_full: Any, data_type: str, value: str) -> IndicatorFacts:
    """Enrichment values first, report_full attributes fill the rest."""
    en = enrichment if isinstance(enrichment, dict) else {}
    at = _attributes(report_full) or {}
    f = IndicatorFacts(vt_link=_vt_link(data_type, value))

    f.detections = _detections(en, at)
    f.flagged_vendors = _vendors(en, at)
    f.reputation = _first(_int(en.get("reputation")), _int(at.get("reputation")))
    f.tags = _strs(en.get("tags")) or _strs(at.get("tags"))
    votes = get_path(at, "total_votes")
    if isinstance(votes, dict):
        f.total_votes = {str(k): v for k, v in votes.items() if _int(v) is not None}
    sev = get_path(at, "threat_severity", "threat_severity_level")
    f.threat_severity = sev if isinstance(sev, str) else None

    f.country = _first(_str(en.get("country")), _str(at.get("country")))
    f.continent = _first(_str(en.get("continent")), _str(at.get("continent")))
    f.as_owner = _first(_str(en.get("as_owner")), _str(at.get("as_owner")))
    f.network = _first(_str(en.get("network")), _str(at.get("network")))
    f.rir = _str(at.get("regional_internet_registry"))
    f.asn = _first(_int(en.get("asn")), _int(at.get("asn")))

    records = at.get("last_dns_records")
    if isinstance(records, list):
        f.resolved_ips = list(dict.fromkeys(
            s for r in records if get_path(r, "type") in ("A", "AAAA") and (s := _str(get_path(r, "value")))))

    rdap = at.get("rdap") if isinstance(at.get("rdap"), dict) else {}
    whois = at.get("whois")
    raw_events = rdap.get("events")
    events = {get_path(e, "event_action"): iso_utc(get_path(e, "event_date"))
              for e in raw_events} if isinstance(raw_events, list) else {}
    f.registrar = _first(_str(en.get("registrar")), _str(at.get("registrar")), _whois(whois, "Registrar"))
    f.created = _first(iso_utc(en.get("creation_date")), iso_utc(at.get("creation_date")),
                       events.get("registration"), iso_utc(_whois(whois, "Creation Date")))
    f.updated = _first(iso_utc(at.get("last_update_date")), events.get("last changed"),
                       iso_utc(_whois(whois, "Updated Date")))
    f.expires = _first(events.get("expiration"), iso_utc(_whois(whois, "Registry Expiry Date")))
    raw_entities = rdap.get("entities")
    entities = [e for e in raw_entities if isinstance(e, dict)] if isinstance(raw_entities, list) else []
    for e in entities:
        if f.registrant is None and "registrant" in (get_path(e, "roles") or []):
            f.registrant = next(iter(_vcard(e, "fn")), None)
    f.contact_emails = list(dict.fromkeys(s for e in entities for s in _vcard(e, "email")))
    f.contact_phones = list(dict.fromkeys(s for e in entities for s in _vcard(e, "tel")))
    ns = rdap.get("nameservers")
    f.name_servers = list(dict.fromkeys(
        s for n in (ns if isinstance(ns, list) else []) if (s := _str(get_path(n, "ldh_name")))))
    f.statuses = _strs(rdap.get("status"))

    f.categories = _str_map(en.get("categories")) or _str_map(at.get("categories"))
    ranks = at.get("popularity_ranks")
    if isinstance(ranks, dict):
        f.popularity_ranks = {str(k): r for k, v in ranks.items() if (r := _int(get_path(v, "rank"))) is not None}

    f.final_url = _first(_str(en.get("final_url")), _str(at.get("last_final_url")))
    f.title = _first(_str(en.get("page_title")), _str(at.get("title")))
    f.http_code = _int(at.get("last_http_response_code"))
    brands = [b.get("name") if isinstance(b, dict) else b for b in at.get("identified_brands") or []] \
        if isinstance(at.get("identified_brands"), list) else []
    brands.append(at.get("main_brand"))
    f.brands = _strs(brands)
    f.threat_names = _strs(at.get("threat_names"))
    links = at.get("outgoing_links")
    f.outgoing_links = len(links) if isinstance(links, list) else None
    f.times_submitted = _int(at.get("times_submitted"))

    f.first_submission = _first(iso_utc(en.get("first_seen")), iso_utc(at.get("first_submission_date")))
    f.last_submission = iso_utc(at.get("last_submission_date"))
    f.last_analysis = _first(iso_utc(en.get("last_seen")), iso_utc(at.get("last_analysis_date")))

    f.meaningful_name = _first(_str(en.get("meaningful_name")), _str(at.get("meaningful_name")))
    f.type_description = _first(_str(en.get("type_description")), _str(at.get("type_description")))
    f.md5, f.sha1, f.sha256 = (_str(at.get(k)) for k in ("md5", "sha1", "sha256"))
    f.threat_label = _first(_str(en.get("threat_label")),
                            _str(get_path(at, "popular_threat_classification", "suggested_threat_label")))
    f.names = _strs(en.get("names")) or _strs(at.get("names"))
    f.size = _first(_int(en.get("size")), _int(at.get("size")))
    sandboxes = at.get("sandbox_verdicts")
    if isinstance(sandboxes, dict):
        f.sandbox_verdicts = [
            (str(k), s) for k, v in sandboxes.items()
            if (s := _first(_str(get_path(v, "category")), _str(get_path(v, "malware_names", 0))))]
    return f
