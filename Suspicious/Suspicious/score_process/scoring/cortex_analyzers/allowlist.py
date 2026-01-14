import logging
from file_process.models import File
from settings.models import (
    AllowListDomain,
    AllowListFile,
    AllowListFiletype,
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
                if AllowListFile.objects.filter(linked_file_hash=file.linked_hash).exists():
                    result.FileAllowList = "Safe FW triggered"
                if AllowListFiletype.objects.filter(filetype=file.filetype).exists():
                    result.FiletypeAllowList = "Safe FTW triggered"

        elif data_type == "url":
            domain = extract_domain(data)
            if domain and AllowListDomain.objects.filter(domain__value=domain).exists():
                result.DomainAllowList = "Safe DW triggered"

    except Exception as exc:
        logger.error("Allow-list check failed: %s", exc)

    return result
