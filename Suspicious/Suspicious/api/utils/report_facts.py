"""Plain facts for the case report, extracted defensively from analyzer payloads.

Pure dict -> dataclass; no ORM, no network. Payload keys may be missing, null or
of the wrong type: every reader goes through get_path and isinstance checks."""
from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from urllib.parse import urlsplit
from typing import Any

import tldextract

from score_process.scoring.enrichment.virustotal import _attributes, _iso, _vt_link

# Bundled snapshot of the public suffix list: no network fetch, no cache directory.
_tld = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=(), fallback_to_snapshot=True)
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
        try:
            return _iso(value)
        except (ValueError, OverflowError, OSError):
            return None
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
        try:
            return value.astimezone(timezone.utc).strftime(_ISO_FMT)
        except (ValueError, OverflowError, OSError):
            return None
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


def _brands(attrs: dict) -> list[str]:
    raw = attrs.get("identified_brands")
    names = [b.get("name") if isinstance(b, dict) else b for b in (raw if isinstance(raw, list) else [])]
    return _strs(names + [attrs.get("main_brand")])


def _vcard(entity: Any, name: str) -> list[str]:
    out: list[str] = []
    items = get_path(entity, "vcard_array")
    for item in items if isinstance(items, list) else []:
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
    flagged = [(str(n), c, _str(r)) for n, c, r in rows if isinstance(n, str) and isinstance(c, str) and c in _CAT_ORDER]
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
    events = {a: iso_utc(get_path(e, "event_date")) for e in (raw_events if isinstance(raw_events, list) else [])
              if isinstance(a := get_path(e, "event_action"), str)}
    f.registrar = _first(_str(en.get("registrar")), _str(at.get("registrar")), _whois(whois, "Registrar"))
    f.created = _first(iso_utc(en.get("creation_date")), iso_utc(at.get("creation_date")),
                       events.get("registration"), iso_utc(_whois(whois, "Creation Date")))
    f.updated = _first(iso_utc(at.get("last_update_date")), events.get("last changed"),
                       iso_utc(_whois(whois, "Updated Date")))
    f.expires = _first(events.get("expiration"), iso_utc(_whois(whois, "Registry Expiry Date")))
    raw_entities = rdap.get("entities")
    entities = [e for e in raw_entities if isinstance(e, dict)] if isinstance(raw_entities, list) else []
    for e in entities:
        roles = get_path(e, "roles")
        if f.registrant is None and isinstance(roles, list) and "registrant" in roles:
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
    f.brands = _brands(at)
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


def apply_fallbacks(facts: IndicatorFacts, sources: list[dict], data_type: str) -> IndicatorFacts:
    """Copy of facts with empty location/category fields filled from DShield, StopForumSpam, Zscaler."""
    out = replace(facts)
    for src in sources:
        name, rep = str(src.get("name") or "").lower(), src.get("report")
        if src.get("failed") or not isinstance(rep, dict):
            continue
        if data_type == "ip" and name.startswith("dshield"):
            out.as_owner = out.as_owner or _str(rep.get("asname"))
            out.country = out.country or _str(rep.get("ascountry"))
            out.network = out.network or _str(rep.get("network"))
        elif data_type == "ip" and name.startswith("stopforumspam"):
            node = rep["ip"] if isinstance(rep.get("ip"), dict) else {}
            asn = _first(*(v for v in (rep.get("asn"), node.get("asn")) if _asn(v) is not None))
            out.asn = out.asn if out.asn is not None else _asn(asn)
            out.country = out.country or _first(_str(rep.get("country")), _str(node.get("country")))
        elif name.startswith("zscaler") and data_type in ("url", "domain", "ip") and not out.categories:
            if cats := _strs(rep.get("urlClassifications")):
                out.categories = {"Zscaler": ", ".join(cats)}
    return out


def _asn(v: Any) -> int | None:
    return int(v) if isinstance(v, str) and v.isascii() and v.isdigit() and len(v) <= 10 else _int(v)


LEGEND = "🔴 malicious / dangerous  🟠 suspicious  🟢 safe  ⚪ failed / unknown / inconclusive"
BAND_ICON = {"Dangerous": "🔴", "Suspicious": "🟠", "Safe": "🟢", "Inconclusive": "⚪"}
BAND_RANK = {"Dangerous": 0, "Suspicious": 1, "Safe": 2, "Inconclusive": 3}
VERDICT_ICON = {"malicious": "🔴", "suspicious": "🟠", "clean": "🟢", "no-data": "⚪"}
_VERDICT_RANK = {"🔴": 0, "🟠": 1, "🟢": 2, "⚪": 3}
_VERDICT_WORD = {"malicious": "malicious", "suspicious": "suspicious", "clean": "safe"}
GROUPS_BY_TYPE = {
    "ip": ("Location", "Whois/RDAP", "Categorization", "VirusTotal"),
    "domain": ("Location", "Whois/RDAP", "Categorization", "VirusTotal"),
    "url": ("URL", "Location", "Categorization", "VirusTotal"),
    "hash": ("Hash", "VirusTotal"),
    "file": ("Hash", "VirusTotal"),
}
_LISTING_SOURCES = ("spamhaus", "misp", "googlesafebrowsing", "phishtank", "zscaler")
_NAMES_MORE, _VENDORS_MORE = " and {n} more", " +{n} more"


@dataclass(frozen=True)
class DetailGroup:
    title: str
    rows: list[tuple[str, str]]


@dataclass(frozen=True)
class ConnectorLine:
    icon: str
    name: str
    label: str
    verdict: str
    tier: int


def band_icon(band: str | None) -> str:
    return BAND_ICON.get(band, "⚪") if isinstance(band, str) else "⚪"


def cap(items: list[str], limit: int, more: str) -> str:
    text = ", ".join(items[:limit])
    return text + more.format(n=len(items) - limit) if len(items) > limit else text


def _pair(name: str, result: str | None) -> str:
    return f"{name} ({result})" if result else name


def detail_groups(facts: IndicatorFacts, data_type: str) -> list[DetailGroup]:
    f = facts
    det = f.detections
    votes = ", ".join(f"{k} {v}" for k, v in f.total_votes.items())
    pops = ", ".join(f"{k} #{v}" for k, v in f.popularity_ranks.items())
    raw: dict[str, list[tuple[str, Any]]] = {
        "Location": [
            ("IP addresses", cap(f.resolved_ips, 5, _NAMES_MORE)), ("Country", f.country),
            ("ASN", f"AS{f.asn}" if f.asn is not None else None), ("AS owner", f.as_owner),
            ("Network", f.network), ("RIR", f.rir)],
        "Whois/RDAP": [
            ("Registrar", f.registrar), ("Registrant", f.registrant),
            ("Contact emails", ", ".join(f.contact_emails)), ("Contact phones", ", ".join(f.contact_phones)),
            ("Name servers", ", ".join(f.name_servers)), ("Status", ", ".join(f.statuses)),
            ("Created", f.created), ("Updated", f.updated), ("Expires", f.expires)],
        "Categorization": list(f.categories.items()),
        "URL": [
            ("Final URL", f.final_url), ("Title", f.title), ("HTTP code", f.http_code),
            ("Brands", ", ".join(f.brands)), ("First submitted", f.first_submission),
            ("Times submitted", f.times_submitted), ("Outgoing links", f.outgoing_links)],
        "Hash": [
            ("File name", f.meaningful_name), ("Other names", cap(f.names, 5, _NAMES_MORE)),
            ("File type", f.type_description), ("Size", f.size), ("MD5", f.md5), ("SHA-1", f.sha1),
            ("SHA-256", f.sha256), ("Threat label", f.threat_label), ("First submitted", f.first_submission),
            ("Last submitted", f.last_submission), ("Last analysed", f.last_analysis)],
        "VirusTotal": [
            ("Detections", f"{det[0]}/{det[2]}" if det else None),
            ("Flagged by", cap([_pair(n, r) for n, r in f.flagged_vendors], 10, _VENDORS_MORE)),
            ("Sandbox verdicts", cap([_pair(n, r) for n, r in f.sandbox_verdicts], 10, _VENDORS_MORE)),
            ("Reputation", f.reputation), ("Community votes", votes), ("Threat severity", f.threat_severity),
            ("Tags", ", ".join(f.tags)), ("Popularity", pops)],
    }
    groups = []
    for title in GROUPS_BY_TYPE.get(data_type, ()):
        rows = [(k, str(v)) for k, v in raw[title] if v is not None and str(v) != ""]
        if rows:
            groups.append(DetailGroup(title, rows))
    return groups


def _is_vt(src: dict) -> bool:
    return str(src.get("name") or "").lower().startswith("virustotal") or \
        get_path(src.get("enrichment"), "source") == "virustotal"


def connector_lines(sources: list[dict], facts: IndicatorFacts, vt_source: dict | None = None) -> list[ConnectorLine]:
    lines = []
    for src in sources:
        failed, verdict = bool(src.get("failed")), str(src.get("verdict") or "no-data")
        icon = "⚪" if failed else VERDICT_ICON.get(verdict, "⚪")
        if failed:
            label = "failed"
        elif _is_vt(src) and facts.detections and (vt_source is None or src is vt_source):
            label = f"{facts.detections[0]}/{facts.detections[2]} detections"
        else:
            label = _str(src.get("evidence")) or _VERDICT_WORD.get(verdict, "no data")
        tier = src.get("tier") if isinstance(src.get("tier"), int) else 9
        lines.append(ConnectorLine(icon, str(src.get("name") or ""), label, verdict, tier))
    return sort_connector_lines(lines)


def sort_connector_lines(lines: list[ConnectorLine]) -> list[ConnectorLine]:
    """Worst verdict first, then tier, then name."""
    return sorted(lines, key=lambda ln: (_VERDICT_RANK[ln.icon], ln.tier, ln.name.lower()))


def _host(value: str) -> str | None:
    try:
        host = urlsplit(value if "//" in value else "//" + value).hostname
    except ValueError:
        return None
    return host.lower() if host else None


def _registrable(host: str) -> str:
    """Registrable domain (eTLD+1); an unknown TLD (.test) falls back to the last two labels."""
    ext = _tld(host)
    if ext.suffix:
        return ext.top_domain_under_public_suffix
    return ".".join(host.split(".")[-2:]) if ext.subdomain else host


def key_findings(facts: IndicatorFacts, sources: list[dict], value: str, data_type: str, now: datetime) -> list[str]:
    out: list[str] = []
    for src in sorted(sources, key=lambda s: str(s.get("name") or "").lower()):
        name = str(src.get("name") or "")
        if (not src.get("failed") and name.lower().startswith(_LISTING_SOURCES)
                and src.get("verdict") in ("malicious", "suspicious")):
            ev = _str(src.get("evidence"))
            out.append(f"Listed by {name}: {ev}" if ev else f"Listed by {name}")
    if facts.detections and facts.detections[0] > 0:
        out.append(f"{facts.detections[0]} of {facts.detections[2]} VirusTotal engines flag it as malicious")
    if threat := facts.threat_label or next(iter(facts.threat_names), None):
        out.append(f"Threat name: {threat}")
    host = _host(value) or ""
    for brand in facts.brands:
        key = re.sub(r"[^a-z0-9]", "", brand.lower())
        if key and host and key not in re.sub(r"[^a-z0-9]", "", _registrable(host)):
            out.append(f"Shows the {brand} brand on another domain")
            break
    if data_type in ("domain", "url") and (created := iso_utc(facts.created)):
        days = (now - datetime.strptime(created, _ISO_FMT).replace(tzinfo=timezone.utc)).days
        if 0 <= days < 30:
            out.append("Domain registered today" if days == 0 else f"Domain registered {days} days ago")
    if data_type == "url" and facts.final_url and (final := _host(facts.final_url)) \
            and _registrable(final) != _registrable(host):
        out.append(f"Redirects to {final}")
    for source, rank in facts.popularity_ranks.items():
        if rank <= 1000:
            out.append(f"Ranked #{rank} by {source}")
            break
    return out[:5]
