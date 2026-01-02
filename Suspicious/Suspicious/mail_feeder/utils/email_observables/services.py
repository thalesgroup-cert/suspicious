import os
import json
import logging
from typing import Dict, Any
from .models import ObservablesResult
from .utils import add_artifact, add_file_attachment, process_attachments
from mail_feeder.mail_utils.meioc import email_analysis
from mail_feeder.utils.process_artifacts.artifacts import ArtifactService
from mail_feeder.utils.process_attachments.attachments import AttachmentService

FILE_TEMP_PATH = "/tmp/files"
logger = logging.getLogger("tasp.cron.fetch_and_process_emails")
class EmailObservablesService:
    """Service for extracting observables from emails."""

    def __init__(self):
        self.logger = logger

    def handle_rich_observables(
        self,
        filename: str,
        mail_instance: Any,
        email_data: Dict[str, Any],
        workdir: str
    ) -> None:
        try:
            rich_observables = self.extract_observables(filename, email_data, workdir)
            if rich_observables.artifacts:
                artifact_service = ArtifactService()
                artifact_service.handle_artifacts(rich_observables.artifacts, mail_instance)
            if rich_observables.files:
                attachment_service = AttachmentService()
                attachment_service.handle_attachments(rich_observables.files,mail_instance)
        except Exception as e:
            self.logger.error(f"Error handling rich observables: {e}")
            raise

    def extract_observables(self, filename: str, mail: Dict[str, Any], workdir: str) -> ObservablesResult:
        artifacts = []
        files = {}
        processed_files = set()
        filepath = self._resolve_file_path(filename, workdir)

        try:
            iocextract = json.loads(email_analysis(filepath, True, True, True, False))
        except Exception as e:
            self.logger.error(f"email_analysis failed: {e}")
            iocextract = {}

        # Extract basic observables
        self._extract_basic_observables(iocextract, artifacts)

        # Clean up temporary file if msg
        if mail.get("mailFormat") == "msg":
            os.remove(filepath)
            filepath = os.path.join(FILE_TEMP_PATH, filename, f"{filename}.msg")

        # Process attachments
        attachment_id = 0
        attachment_id = add_file_attachment(files, processed_files, artifacts, filepath, attachment_id, ["reported email"])
        attachment_id = self._process_related_attachments(workdir, mail, attachment_id, artifacts, files, processed_files)

        return ObservablesResult(artifacts=artifacts, files=files)

    def _resolve_file_path(self, filename: str, workdir: str) -> str:
        for ext in [".eml", ".msg"]:
            path = os.path.join(workdir, f"{filename}{ext}")
            if os.path.exists(path):
                return path

        for alt in ["user_submission.eml", "user_submission.msg"]:
            path = os.path.join(workdir, alt)
            if os.path.exists(path):
                return path

        raise FileNotFoundError(f"No email file found for {filename} in {workdir}")

    def _extract_basic_observables(self, iocextract: Dict[str, Any], artifacts: list) -> None:
        
        # URLs
        for _, url in (iocextract.get("urls") or {}).items():
            if not url.startswith("mailto"):
                add_artifact(artifacts, "url", url)

        # Domains
        for _, domain in (iocextract.get("domains") or {}).items():
            add_artifact(artifacts, "domain", domain)

        # IPs
        for ip in (iocextract.get("body_ip") or []):
            add_artifact(artifacts, "ip", str(ip), ["Body"])

        # Emails
        for email in (iocextract.get("body_email") or []):
            add_artifact(artifacts, "mail", str(email), ["Body"])

        # Hashes
        for hash_val in (iocextract.get("body_hash") or []):
            add_artifact(artifacts, "hash", str(hash_val), ["Body"])


    def _process_related_attachments(
        self,
        workdir: str,
        mail: Dict[str, Any],
        attachment_id: int,
        artifacts: list,
        files: dict,
        processed_files: set
    ) -> int:
        linked_att_path = os.path.join(workdir, "attachments")
        attachment_id = process_attachments(linked_att_path, attachment_id, artifacts, files, processed_files, ["from reported email"])

        if "parent" in mail:
            parent_directory = os.path.join(workdir, mail["parent"])
            attachment_id = process_attachments(parent_directory, attachment_id, artifacts, files, processed_files, ["from parent email"])

        return attachment_id
