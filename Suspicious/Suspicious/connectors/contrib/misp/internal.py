"""
The organisation's own domains, kept out of MISP.

Recipients of a reported mail are company staff and company domains are the
victims, not indicators: neither belongs in an IOC feed shared outside.
"""
from __future__ import annotations
import re

_ADDRESS = re.compile(r"[\w.+'-]+@([\w-]+(?:\.[\w-]+)+)")


def company_domains() -> frozenset[str]:
    """Watcher legit domains plus the organisation's own domains."""
    from mail_feeder.utils.user_creation.creation import _own_domains
    from settings.models import WatcherLegitDomain

    legit = WatcherLegitDomain.objects.values_list("domain__value", flat=True)
    return frozenset(d.strip().lower().rstrip(".") for d in [*legit, *_own_domains()] if d)


def allow_listed_domains() -> frozenset[str]:
    """Exact allow-listed domains (no subdomain matching, as before)."""
    from settings.models import AllowListDomain

    values = AllowListDomain.objects.values_list("domain__value", flat=True)
    return frozenset(v.strip().lower() for v in values if v)


def is_company_domain(domain: str, domains) -> bool:
    domain = (domain or "").strip().lower().rstrip(".")
    return bool(domain) and any(domain == d or domain.endswith("." + d) for d in domains)


def external_addresses(value: str | None, domains) -> str:
    """The addresses in a header value that are not on a company domain,
    comma-separated; "" when none are left."""
    kept = [m.group(0) for m in _ADDRESS.finditer(value or "")
            if not is_company_domain(m.group(1), domains)]
    return ", ".join(dict.fromkeys(kept))
