import os
import email
import logging
from typing import Optional

from mail_feeder.email_parser.parser import parse_email
from mail_feeder.web_submission.models import WebSubmissionConfig

from mail_feeder.case_creator.creator import CaseCreationService
from mail_feeder.case_creator.models import CaseInputData

from mail_feeder.email_handler.email_handler import EmailHandlerService

from mail_feeder.email_info.email_info import MailInfoService

from mail_feeder.utils.user_creation.creation import UserCreationService


from .models import MailSubmissionData
from .utils import safe_execution, flatten_id_lists, extract_email_address
from .handlers import Handlers


logger = logging.getLogger("global_submissions")
fetch_mail_logger = logging.getLogger("tasp.cron.fetch_and_process_emails")

class GlobalSubmissionService:
    """
    Service for processing global email submissions, including artifacts, attachments,
    mail headers, and mail bodies.
    """
    def process_single_email(self, submission: MailSubmissionData):
        """
        Process a single email file end-to-end.
        """
        with safe_execution(f"processing email {submission.email_id}"):
            filepath = os.path.join(submission.workdir, submission.filename)
            with open(filepath, "rb") as f:
                msg = email.message_from_binary_file(f)

            mail_instance = parse_email(msg, submission.workdir,
                                        submission.email_id,
                                        submission.user if submission.is_submitted else None)
            
            instance = EmailHandlerService().handle_mail(mail_instance, submission.workdir)

            if not instance:
                fetch_mail_logger.error(f"Email instance processing failed for {submission.email_id}")
                return None

            # Handle post-processing based on submission type
            if submission.is_submitted:
                self.finalize_submission(instance, WebSubmissionConfig(user_email=submission.user, workdir=submission.workdir))
            else:
                self._handle_instance_for_minio(instance, submission.email_id, submission.workdir)
            
            MailInfoService().create_mail_info(instance)
            return instance

    def finalize_submission(self, instance, config: WebSubmissionConfig):
        """
        Finalize a single email instance submitted via web.
        """
        email_id = os.path.basename(config.workdir)

        with safe_execution(f"finalizing web submission {email_id}"):
            instance.reportedBy = config.user_email
            instance.save()

            mail_zip = self._get_mail_zip_path(config.workdir, email_id)
            self._handle_common_instance_tasks(instance, email_id, mail_zip)
            fetch_mail_logger.info(f"Finalized web submission for email_id={email_id}")

    def _get_mail_zip_path(self, workdir: str, email_id: str) -> str:
        return os.path.join(os.path.dirname(workdir), f"{email_id}.tar.gz")

    def _handle_instance_for_minio(self, instance, email_id: str, workdir: str):
        """
        Handle post-processing of a MinIO-parsed email instance.
        """
        with safe_execution(f"finalizing MinIO email {email_id}"):
            user_email = self._extract_reported_by_from_user_submission(workdir)
            instance.reportedBy = user_email
            instance.save()

            mail_zip = self._get_mail_zip_path(workdir, email_id)
            self._handle_common_instance_tasks(instance, email_id, mail_zip)

    def _extract_reported_by_from_user_submission(self, workdir: str) -> Optional[str]:
        """
        Extract the reporter's email address from 'user_submission.eml'.
        """
        path = os.path.join(workdir, "user_submission.eml")
        with safe_execution("extracting reportedBy"):
            with open(path, "r") as f:
                user_submission = email.message_from_file(f)
            from_header = user_submission.get("From")
            email_addr = extract_email_address(from_header)
            if not email_addr:
                fetch_mail_logger.warning(f"No valid email found in {path}")
            return email_addr

    def list_eml_files(self, workdir: str, prefix: str = "") -> list[str]:
        """
        List all `.eml` files in a directory optionally filtering by prefix.
        """
        all_files = os.listdir(workdir)
        return [f for f in all_files if f.endswith(".eml") and f.startswith(prefix)]

    def _handle_common_tasks(self, instance, email_id: str, mail_zip: str):
        """
        Handle artifacts, attachments, headers, bodies, and case creation.
        """
        user = UserCreationService().get_or_create_user(instance.reportedBy)

        artifact_ids = Handlers().handle_artifacts(instance)
        attachment_result = Handlers().handle_attachments(instance, mail_zip)
        attachment_ids, attachment_id_ai = attachment_result.ids, attachment_result.ai_ids

        Handlers().handle_mail_header(instance)
        Handlers().handle_mail_body(instance, email_id)

        related_ids = flatten_id_lists(artifact_ids, attachment_ids)
        CaseCreationService().create_case(CaseInputData(
            mail_instance=instance,
            user=user,
            artifact_ids=related_ids,
            attachment_ids=attachment_ids,
            attachment_ai_ids=attachment_id_ai
        ))
