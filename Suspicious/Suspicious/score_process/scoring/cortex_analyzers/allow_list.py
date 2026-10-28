"""
Allow-list checks for files, filetypes, URLs, domain, and IP IOCs.
"""
import logging

from file_process.models import File
from domain_process.models import Domain
from settings.allow_lists import is_ip_allow_listed, overrides_allow_list
from settings.models import (
    AllowListDomain,
    AllowListFile,
    AllowListFiletype,
    WatcherLegitDomain,
)
from .utils import extract_domain
from .result import AllowListResult

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")

SAFE_FW, SAFE_FTW = "Safe FW triggered", "Safe FTW triggered"
SAFE_DW, SAFE_WL, SAFE_IPW = "Safe DW triggered", "Safe WL triggered", "Safe IPW triggered"
ALLOW_LIST_MARKERS = frozenset({SAFE_FW, SAFE_FTW, SAFE_DW, SAFE_WL, SAFE_IPW})


def is_allow_listed_category(category) -> bool:
    """True for a stored AnalyzerReport.category produced by an allow-list hit."""
    text = category or ""
    return any(marker in text for marker in ALLOW_LIST_MARKERS)


def check_allow_list(data: str, data_type: str) -> AllowListResult:
    result = AllowListResult()

    try:
        if data_type == "file":
            file = File.objects.filter(file_path=data).first()
            if file:
                if AllowListFile.objects.filter(
                    linked_file_hash=file.linked_hash
                ).exists():
                    result.FileAllowList = SAFE_FW

                if AllowListFiletype.objects.filter(
                    filetype=file.filetype
                ).exists():
                    result.FiletypeAllowList = SAFE_FTW

        elif data_type in ("url", "domain"):
            host = (extract_domain(data) if data_type == "url" else data) or ""
            # A URL is stored against its host without "www." (URLHandler.get_domain), so
            # listing example.com must cover www.example.com. An entry added as "www.example.com"
            # still matches, and a deny-listed or monitored bare domain still overrides.
            names = {host.lower(), host.lower().removeprefix("www.")} - {""}

            if names and not any(overrides_allow_list(d) for d in Domain.objects.filter(value__in=names)):
                if AllowListDomain.objects.filter(domain__value__in=names).exists():
                    result.DomainAllowList = SAFE_DW

                elif WatcherLegitDomain.objects.filter(domain__value__in=names).exists():
                    result.DomainAllowList = SAFE_WL

        elif data_type == "ip":
            if is_ip_allow_listed(data):
                result.IpAllowList = SAFE_IPW

    except Exception as exc:
        logger.error("Allow-list check failed for %r (%s): %s", data, data_type, exc)

    return result