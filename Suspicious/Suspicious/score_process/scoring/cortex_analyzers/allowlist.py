# score_process/scoring/cortex_analyzers/allow_list.py
"""
Allow-list checks for files, filetypes, URLs, and domain IOCs.
"""
import logging

from file_process.models import File
from settings.models import (
    AllowListDomain,
    AllowListFile,
    AllowListFiletype,
    WatcherLegitDomain,
)
from .utils import extract_domain
from .models import AllowListResult

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


def check_allow_list(data: str, data_type: str) -> AllowListResult:
    result = AllowListResult()

    try:
        if data_type == "file":
            file = File.objects.filter(file_path=data).first()
            if file:
                if AllowListFile.objects.filter(
                    linked_file_hash=file.linked_hash
                ).exists():
                    result.FileAllowList = "Safe FW triggered"

                if AllowListFiletype.objects.filter(
                    filetype=file.filetype
                ).exists():
                    result.FiletypeAllowList = "Safe FTW triggered"

        elif data_type in ("url", "domain"):
            # For URLs, extract the hostname first; for domain IOCs use as-is.
            domain = extract_domain(data) if data_type == "url" else data

            if domain:
                # Either table matching is sufficient to flag as safe —
                # the two lists serve different purposes (explicit allow-list
                # vs watcher-validated legitimate domain).
                if AllowListDomain.objects.filter(domain__value=domain).exists():
                    result.DomainAllowList = "Safe DW triggered"

                elif WatcherLegitDomain.objects.filter(domain__value=domain).exists():
                    result.DomainAllowList = "Safe WL triggered"

    except Exception as exc:
        logger.error("Allow-list check failed for %r (%s): %s", data, data_type, exc)

    return result