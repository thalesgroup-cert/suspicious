"""Pure header-analysis logic for MailHeaderAnalyzer.

No cortexutils dependency and no network calls — parses a raw email header
block (stdlib `email` only) into a handful of deterministic phishing
signals, then maps them to taxonomy-shaped verdicts. Kept separate from
mail_header_analyzer.py (the cortexutils.Analyzer glue) so it's unit-testable
with zero dependencies, matching AIMailAnalyzer's own mail_analysis.py split.
"""
from __future__ import annotations

import re
from email import message_from_string
from email.utils import parseaddr

_AUTH_RESULT_RE = re.compile(r'\b(spf|dkim|dmarc)\s*=\s*(\w+)', re.IGNORECASE)
_EMBEDDED_ADDRESS_RE = re.compile(r'[\w.+-]+@[\w.-]+\.\w+')


def parse_headers(header_text: str):
    """Parse a raw header block into an email.message.Message."""
    return message_from_string(header_text or "")


def get_domain(address: str) -> str:
    """Lowercased domain from an email address/header value, "" if unparseable."""
    _, addr = parseaddr(address or "")
    if "@" not in addr:
        return ""
    return addr.rsplit("@", 1)[1].lower()


def parse_auth_results(msg) -> dict:
    """Combine every Authentication-Results header's spf/dkim/dmarc verdicts.

    Multiple Authentication-Results headers can be present (one per hop);
    a mechanism counts as "pass" only if every occurrence of it passed,
    otherwise the first non-pass verdict seen is reported, otherwise "none"
    if the mechanism never appeared.
    """
    verdicts = {"spf": [], "dkim": [], "dmarc": []}
    for header_value in msg.get_all("Authentication-Results", []):
        for mechanism, result in _AUTH_RESULT_RE.findall(header_value):
            verdicts[mechanism.lower()].append(result.lower())

    result = {}
    for mechanism, seen in verdicts.items():
        if not seen:
            result[mechanism] = "none"
        elif all(v == "pass" for v in seen):
            result[mechanism] = "pass"
        else:
            result[mechanism] = next(v for v in seen if v != "pass")
    return result


def check_domain_mismatch(msg, header_name: str) -> dict:
    """Compare From's domain against another address header's domain."""
    from_domain = get_domain(msg.get("From", ""))
    other_header = msg.get(header_name)
    if not other_header:
        return {"present": False, "match": True, "from_domain": from_domain, "other_domain": ""}
    other_domain = get_domain(other_header)
    return {
        "present": True,
        "match": bool(other_domain) and other_domain == from_domain,
        "from_domain": from_domain,
        "other_domain": other_domain,
    }


def check_display_name_spoofing(msg) -> dict:
    """True if the From display name embeds an address whose domain differs
    from the actual From address domain (the "Legit Bank <billing@legit.com>"
    display name on a from-domain that isn't legit.com trick)."""
    display_name, addr = parseaddr(msg.get("From", ""))
    from_domain = get_domain(addr)
    embedded = _EMBEDDED_ADDRESS_RE.findall(display_name or "")
    spoofed = [e for e in embedded if get_domain(e) and get_domain(e) != from_domain]
    return {"spoofed": bool(spoofed), "display_name": display_name or "", "embedded_addresses": spoofed}


def build_verdict(report: dict) -> list:
    """Turn a raw signals report into taxonomy-shaped entries:
    [{"level": ..., "predicate": ..., "value": ...}, ...]
    mail_header_analyzer.py wraps each entry with self.build_taxonomy(...).
    """
    taxonomies = []

    auth = report["auth_results"]
    for mechanism in ("spf", "dkim", "dmarc"):
        verdict = auth[mechanism]
        if verdict == "pass":
            level = "safe"
        elif verdict == "none":
            level = "info"
        else:
            level = "suspicious"
        taxonomies.append({"level": level, "predicate": mechanism.upper(), "value": verdict})

    for predicate, key in (("ReplyToMatch", "reply_to"), ("ReturnPathMatch", "return_path")):
        check = report[key]
        if not check["present"]:
            level, value = "info", "absent"
        elif check["match"]:
            level, value = "safe", "match"
        else:
            level, value = "suspicious", f"{check['from_domain']} != {check['other_domain']}"
        taxonomies.append({"level": level, "predicate": predicate, "value": value})

    spoof = report["display_name_spoofing"]
    if spoof["spoofed"]:
        taxonomies.append({
            "level": "malicious",
            "predicate": "DisplayNameSpoofing",
            "value": ", ".join(spoof["embedded_addresses"]),
        })
    else:
        taxonomies.append({"level": "safe", "predicate": "DisplayNameSpoofing", "value": "none"})

    return taxonomies


def analyze_message(msg) -> dict:
    """Full pipeline on an already-parsed email.message.Message: signals +
    taxonomy-shaped verdict. Works the same whether msg came from a bare
    header block or a full .eml (only header access is used, never body)."""
    report = {
        "auth_results": parse_auth_results(msg),
        "reply_to": check_domain_mismatch(msg, "Reply-To"),
        "return_path": check_domain_mismatch(msg, "Return-Path"),
        "display_name_spoofing": check_display_name_spoofing(msg),
    }
    report["taxonomies"] = build_verdict(report)
    return report


def analyze(header_text: str) -> dict:
    """Full pipeline: raw header text -> signals + taxonomy-shaped verdict."""
    return analyze_message(parse_headers(header_text))
