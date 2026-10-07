"""Indicators of compromise for a campaign alert, from one reported mail."""
from __future__ import annotations

import email
import ipaddress
import re
import zlib
from dataclasses import dataclass, field
from email.header import decode_header, make_header
from email.utils import getaddresses
from typing import Callable
from urllib.parse import urlparse

from connectors.contrib.thehive.utils import extract_urls, is_domain_in_campaign_allow_list

MAX_URLS = 100
_TEXT_EXTENSIONS = (".html", ".htm", ".txt", ".eml", ".csv", ".xml", ".svg")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_FLATE_STREAM = re.compile(rb"stream\r?\n(.*?)\r?\nendstream", re.DOTALL)
_AUTH_FAIL = re.compile(r"\b(spf|dkim|dmarc)=(fail|softfail|permerror)\b", re.IGNORECASE)


@dataclass
class Iocs:
    urls: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    display_names: list[str] = field(default_factory=list)
    message_ids: list[str] = field(default_factory=list)
    subjects: list[str] = field(default_factory=list)
    filenames: list[str] = field(default_factory=list)
    hashes: list[str] = field(default_factory=list)
    auth_failures: list[str] = field(default_factory=list)


def _add(target: list, value: str) -> None:
    if value and value not in target:
        target.append(value)


def _refang(text: str) -> str:
    return re.sub(r"hxxp", "http", text.replace("[.]", ".").replace("(.)", "."), flags=re.IGNORECASE)


def _decode(value: str) -> str:
    try:
        return str(make_header(decode_header(value)))
    except Exception:  # noqa: BLE001
        return value


def _pdf_text(data: bytes) -> str:
    parts = [data.decode("latin-1")]
    for stream in _FLATE_STREAM.findall(data):
        try:
            parts.append(zlib.decompress(stream).decode("latin-1"))
        except zlib.error:
            continue
    return "\n".join(parts)


def _attachment_text(name: str, data: bytes) -> str:
    lowered = name.lower()
    if lowered.endswith(".pdf") or data.startswith(b"%PDF"):
        return _pdf_text(data)
    if lowered.endswith(_TEXT_EXTENSIONS):
        return data.decode("utf-8", "replace")
    return ""


def _mail_bodies(material) -> list[str]:
    """Decoded text and HTML parts of the raw mail.

    The stored .txt/.html are flattened (line breaks dropped), which glues the
    word after a URL onto it; the raw mail keeps the original text. The stored
    parts are the fallback when there is no raw mail.
    """
    bodies = []
    if material.eml:
        for part in email.message_from_bytes(material.eml).walk():
            if part.get_content_type() in ("text/plain", "text/html") and not part.get_filename():
                payload = part.get_payload(decode=True)
                if payload:
                    bodies.append(payload.decode(part.get_content_charset() or "utf-8", "replace"))
    return bodies or [material.html, material.text]


def _public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def _under(domain: str, base: str) -> bool:
    return domain == base or domain.endswith("." + base)


def extract_iocs(
    material, kept, skipped, *, own_domains=(),
    is_allowed: Callable[[str], bool] = is_domain_in_campaign_allow_list,
) -> Iocs:
    """Collect the indicators a responder would pivot on.

    Domains of the organisation itself and allow-listed domains are dropped:
    they are the victims or known-good infrastructure, not indicators.
    """
    iocs = Iocs()

    def ignored(domain: str) -> bool:
        return any(_under(domain, d.lower()) for d in own_domains if d) or is_allowed(domain)

    def take_domain(domain: str) -> None:
        domain = (domain or "").lower().rstrip(".")
        if domain and not ignored(domain):
            _add(iocs.domains, domain)

    headers = email.message_from_string(material.headers or "")

    # URLs: both bodies and every readable attachment
    texts = _mail_bodies(material) + [_attachment_text(a.name, a.data) for a in kept]
    for text in texts:
        for url in extract_urls(_refang(text or "")):
            host = (urlparse(url).hostname or "").lower().rstrip(".")
            if not host or (not _is_ip(host) and ignored(host)):
                continue
            if len(iocs.urls) < MAX_URLS:
                _add(iocs.urls, url)
            if _is_ip(host):
                if _public_ip(host):
                    _add(iocs.ips, host)
            else:
                take_domain(host)

    # sender-side identities
    for header in ("From", "Reply-To", "Return-Path", "Sender"):
        for display, address in getaddresses(headers.get_all(header, [])):
            if "@" not in address:
                continue
            domain = address.rsplit("@", 1)[1].lower()
            if ignored(domain):
                continue
            _add(iocs.emails, address.lower())
            take_domain(domain)
            if header == "From" and display:
                _add(iocs.display_names, _decode(display))

    for message_id in headers.get_all("Message-ID", []):
        _add(iocs.message_ids, message_id.strip())
    for subject in headers.get_all("Subject", []):
        _add(iocs.subjects, _decode(subject).replace("\r\n", " ").strip())

    # network path
    for received in headers.get_all("Received", []):
        for candidate in _IP_RE.findall(received):
            if _public_ip(candidate):
                _add(iocs.ips, candidate)
    for origin in headers.get_all("X-Originating-IP", []):
        for candidate in _IP_RE.findall(origin):
            if _public_ip(candidate):
                _add(iocs.ips, candidate)

    for result in headers.get_all("Authentication-Results", []) + headers.get_all("Received-SPF", []):
        for mechanism, outcome in _AUTH_FAIL.findall(result):
            _add(iocs.auth_failures, f"{mechanism.lower()}={outcome.lower()}")
    if any("fail" in (v or "").lower() for v in headers.get_all("Received-SPF", [])):
        _add(iocs.auth_failures, "spf=fail")

    # files: hash and name what we keep, and what was too big to upload
    for att in kept:
        _add(iocs.filenames, att.name)
        _add(iocs.hashes, att.sha256)
    for name, sha, _size, reason in skipped:
        if reason.startswith("too large"):
            _add(iocs.filenames, name)
            _add(iocs.hashes, sha)
    return iocs


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False
