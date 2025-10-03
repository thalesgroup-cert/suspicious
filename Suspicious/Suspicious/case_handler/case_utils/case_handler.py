# case_handler.py

import logging
import json
from pathlib import Path
from typing import Optional, Tuple, Dict, Union

from cortex_job.models import AnalyzerReport
from case_handler.case_utils.case_creator import CaseCreator

from hash_process.hash_utils.hash_handler import HashHandler
from file_process.file_utils.file_handler import FileHandler
from ip_process.ip_utils.ip_handler import IPHandler
from url_process.url_utils.url_handler import URLHandler

from case_handler.case_utils.form_handlers.mail.mail_form import MailFormHandler

from settings.models import (
    AllowListDomain,
    AllowListFile,
    AllowListFiletype,
)
from cortex_job.cortex_utils.cortex_and_job_management import CortexJob

logger = logging.getLogger(__name__)

CONFIG_PATH = "/app/settings.json"
with open(CONFIG_PATH) as config_file:
    config = json.load(config_file)

# Tagging constants
TAG_STATUS_TODO = "To Do_User"
TAG_KEY_STATUS = "Status"
TAG_RESEND = "to_resend"

DEFAULT_CASE_BASE_PATH = Path("/app/case")
TEMP_DIR = Path("/app/submissions")


class CaseHandler:
    """
    Orchestrates processing of file, URL, IP, hash, and mail inputs,
    including allow_listing, analysis, and case creation.
    """

    def __init__(
        self,
        request,
        file_form,
        url_form,
        other_form,
        base_case_path: Union[str, Path] = DEFAULT_CASE_BASE_PATH,
    ):
        self.request = request
        self.file_form = file_form
        self.url_form = url_form
        self.other_form = other_form
        self.base_case_path = Path(base_case_path)

    def validate_forms(self) -> Dict[str, Optional[object]]:
        """
        Validate all forms and dispatch to handlers accordingly.
        Returns instances of each processed item along with allow_listing status.
        """
        result = dict(
            file_instance=None,
            mail_instance=None,
            ip_instance=None,
            url_instance=None,
            hash_instance=None,
            allow_listed=False,
        )

        if self.file_form.is_valid():
            file = self.file_form.cleaned_data.get("file")
            if file and file.name.lower().endswith((".eml", ".msg")):
                result["mail_instance"] = MailFormHandler(
                    self.request.user, base_path=self.base_case_path
                ).handle(file)
            else:
                fi, hi, wl = self._handle_file_form(result["allow_listed"])
                result.update(file_instance=fi, hash_instance=hi, allow_listed=wl)

        if self.url_form.is_valid():
            ui, wl = self._handle_url_form(result["allow_listed"])
            result.update(url_instance=ui, allow_listed=wl)

        if self.other_form.is_valid():
            ii, hi, wl = self._handle_other_form(result["allow_listed"])
            result.update(ip_instance=ii, hash_instance=hi, allow_listed=wl)

        return result

    def _handle_file_form(self, allow_listed: bool) -> Tuple[Optional[object], Optional[object], bool]:
        """
        Process non-email file input: scanning, hashing, allow_listing or analysis.
        """
        file = self.file_form.cleaned_data.get("file")
        if not file:
            return None, None, allow_listed

        try:
            file_inst, hash_inst = FileHandler.handle_file(file)
            if not file_inst or not hash_inst:
                return file_inst, hash_inst, allow_listed

            if AllowListFile.objects.filter(linked_file_hash=hash_inst).exists() or AllowListFiletype.objects.filter(filetype=file_inst.filetype).exists():
                self._allow_list_file(file_inst, hash_inst)
                return file_inst, hash_inst, True

            self._launch_analysis(file_inst, hash_inst, data_type="file")
            return file_inst, hash_inst, False

        except Exception:
            logger.exception("Error processing file form")
            return None, None, allow_listed

    def _allow_list_file(self, file_inst, hash_inst):
        file_inst.update_allow_listed()
        hash_inst.update_allow_listed()
        logger.info("File and hash marked as allow_listed.")

    def _handle_url_form(self, allow_listed: bool) -> Tuple[Optional[object], bool]:
        """
        Process URL submission: parse, check allow_list, or analyze.
        """
        url = self.url_form.cleaned_data.get("url")
        if not url:
            return None, allow_listed

        try:
            url_inst, domain = URLHandler().handle_url(url)
            if url_inst and domain:
                if not AllowListDomain.objects.filter(domain=domain).exists():
                    self._launch_analysis(url_inst, None, data_type="url")
                    return url_inst, False
                url_inst.update_allow_listed()
                return url_inst, True
        except Exception:
            logger.exception("Error processing URL form")
        return None, allow_listed

    def _handle_other_form(self, allow_listed: bool) -> Tuple[Optional[object], Optional[object], bool]:
        """
        Process IP or hash input depending on format.
        """
        other = self.other_form.cleaned_data.get("other")
        if not other:
            return None, None, allow_listed

        try:
            is_ip = IPHandler().validate_ip(other)
            is_hash = HashHandler().validate_hash(other)
            if is_ip:
                ip_inst = IPHandler().handle_ip(other)
                if ip_inst:
                    self._launch_analysis(ip_inst, ip_inst, data_type="ip")
                return ip_inst, None, allow_listed

            if is_hash:
                hash_inst = HashHandler().handle_hash(other)
                if hash_inst:
                    if AllowListFile.objects.filter(linked_file_hash=hash_inst).exists():
                        hash_inst.update_allow_listed()
                        return None, hash_inst, True
                    self._launch_analysis(hash_inst, None, data_type="hash")
                return None, hash_inst, False

        except Exception:
            logger.exception("Error processing other form")
        return None, None, allow_listed

    def handle_case(
        self,
        file_inst=None,
        ip_inst=None,
        url_inst=None,
        hash_inst=None,
        allow_listed=False,
        mail_inst=None,
    ):
        """
        Create a case in the system using user and provided instances.
        """
        ctx = dict(
            file_instance=file_inst,
            mail_instance=mail_inst,
            ip_instance=ip_inst,
            url_instance=url_inst,
            hash_instance=hash_inst,
            allow_listed=allow_listed,
        )
        logger.debug("Creating case with: %s", ctx)
        try:
            case = CaseCreator(self.request.user).create_case(**ctx)
            logger.info("Case created: %s", case)
            return case
        except Exception:
            logger.exception("Failed to create case")
            return None

    def _launch_analysis(self, instance, hash_inst, data_type: str) -> list:
        """
        Launch Cortex analysis and update AnalyzerReport accordingly.
        """ 
        existing = AnalyzerReport.objects.filter(**{data_type: instance}).values_list("id", flat=True)
        if existing:
            return list(existing)

        ids = CortexJob().launch_cortex_jobs(value=instance, data_type=data_type)

        if data_type == "file" and hash_inst:
            self._launch_analysis(hash_inst, None, "hash")

        AnalyzerReport.objects.filter(cortex_job_id__in=ids).update(**{data_type: instance})
        return list(ids)
