"""
The organisation's own domains, kept out of MISP.

Recipients of a reported mail are company staff and company domains are the
victims, not indicators: neither belongs in an IOC feed shared outside.
"""
from __future__ import annotations
import re
from urllib.parse import urlsplit

_ADDRESS = re.compile(r"[\w.+'-]+@([\w-]+(?:\.[\w-]+)+)")


def company_domains() -> frozenset[str]:
    """Watcher legit domains plus the organisation's own domains."""
    from mail_feeder.utils.user_creation.creation import _own_domains
    from settings.models import WatcherLegitDomain

    legit = WatcherLegitDomain.objects.values_list("domain__value", flat=True)
    return frozenset(d.strip().lower().rstrip(".") for d in [*legit, *_own_domains()] if d)


def allow_listed_domains() -> frozenset[str]:
    """Allow-listed domains; their subdomains are covered too (see is_allow_listed)."""
    from settings.models import AllowListDomain

    values = AllowListDomain.objects.values_list("domain__value", flat=True)
    return frozenset(v.strip().lower().rstrip(".") for v in values if v)


def campaign_domains() -> frozenset[str]:
    """Authorised phishing-simulation domains: withheld from MISP like company
    domains (subdomains included) but still scored Dangerous."""
    from settings.models import CampaignDomainAllowList

    values = CampaignDomainAllowList.objects.values_list("domain__value", flat=True)
    return frozenset(v.strip().lower().rstrip(".") for v in values if v)


def allow_listed_ips() -> frozenset[str]:
    from settings.allow_lists import normalise_ip
    from settings.models import AllowListIp

    return frozenset(normalise_ip(a) for a in AllowListIp.objects.values_list("ip__address", flat=True) if a)


def allow_listed_hashes() -> frozenset[str]:
    from settings.models import AllowListFile

    values = AllowListFile.objects.values_list("linked_file_hash__value", flat=True)
    return frozenset(v.strip().lower() for v in values if v)


def is_company_domain(domain: str, domains) -> bool:
    domain = (domain or "").strip().lower().rstrip(".")
    return bool(domain) and any(domain == d or domain.endswith("." + d) for d in domains)


def is_allow_listed(domain: str, allow_listed) -> bool:
    return is_company_domain(domain, allow_listed)


def url_host(address: str | None) -> str:
    """Lower-cased host of a URL ("" when there is none). Credentials in the
    authority part are ignored, so https://corp.example@evil.test/ is evil.test."""
    value = (address or "").strip()
    if "//" not in value:
        value = "//" + value
    try:
        host = urlsplit(value).hostname
    except ValueError:
        return ""
    return (host or "").lower().rstrip(".")


def _split_addresses(value, domains) -> tuple[list[str], list[str]]:
    if isinstance(value, (list, tuple)):
        value = ", ".join(str(v) for v in value)
    company, external = [], []
    for m in _ADDRESS.finditer(value or ""):
        (company if is_company_domain(m.group(1), domains) else external).append(m.group(0))
    return company, external


def external_addresses(value, domains) -> str:
    """The addresses in a header value that are not on a company domain,
    comma-separated; "" when none are left."""
    return ", ".join(dict.fromkeys(_split_addresses(value, domains)[1]))


def company_addresses(value, domains) -> list[str]:
    """The addresses in a header value that are on a company domain."""
    return list(dict.fromkeys(_split_addresses(value, domains)[0]))
