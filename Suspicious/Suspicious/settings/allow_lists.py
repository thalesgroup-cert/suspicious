"""Allow-list lookups shared by job launch, scoring and the MISP connector."""
import ipaddress

from settings.models import AllowListIp, CampaignDomainAllowList, DenyListDomain, WatcherMonitoredDomain


def normalise_ip(address) -> str:
    """Compressed form, so '0:0:0:0:0:0:0:1' and '::1' compare equal.
    Unparseable input comes back stripped (it simply will not match)."""
    value = (address or "").strip()
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError:
        return value


def is_ip_allow_listed(address) -> bool:
    return AllowListIp.objects.filter(ip__address=normalise_ip(address)).exists()


def overrides_allow_list(domain) -> bool:
    """Deny-listed, Watcher-monitored and campaign domains are never treated as allow-listed."""
    if domain is None:
        return False
    return (DenyListDomain.objects.filter(domain=domain).exists()
            or WatcherMonitoredDomain.objects.filter(domain=domain).exists()
            or CampaignDomainAllowList.objects.filter(domain=domain).exists())
