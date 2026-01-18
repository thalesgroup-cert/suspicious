import os
import email
import logging
from typing import Optional

from mail_feeder.email_parser.parser import parse_email
from mail_feeder.web_submission.models import WebSubmissionConfig

from mail_feeder.case_creator.creator import CaseCreatorService
from mail_feeder.case_creator.models import CaseInputData

from mail_feeder.email_handler.email_handler import EmailHandlerService

from mail_feeder.email_info.email_info import MailInfoService

from mail_feeder.utils.user_creation.creation import UserCreationService


from .models import MailSubmissionData
from .utils import safe_execution, flatten_id_lists, extract_email_address
from .handlers import Handlers


fetch_mail_logger = logging.getLogger("tasp.cron.fetch_and_process_emails")

class GlobalSubmissionService:
    """
    Service for processing global email submissions, including artifacts, attachments,
    mail headers, and mail bodies.
    """
    def process_single_email(self, submission: MailSubmissionData):
        with safe_execution(f"processing email {submission.email_id}"):
            filepath = os.path.join(submission.workdir, submission.filename)

            with open(filepath, "rb") as f:
                raw_bytes = f.read()

            msg = email.message_from_bytes(raw_bytes)

            mail_instance = parse_email(
                msg,
                submission.workdir,
                submission.email_id,
                submission.user if submission.is_submitted else None
            )

            instance = EmailHandlerService().handle_mail(mail_instance, submission.workdir)

            fetch_mail_logger.debug(
                f"Processed email instance: {instance.mail_id if instance else 'None'}"
            )

            if not instance:
                fetch_mail_logger.error(
                    f"Email instance processing failed for {submission.email_id}"
                )
                return None
            instance.save()
            # Handle post-processing based on submission type
            if submission.is_submitted:
                fetch_mail_logger.debug(f"Finalizing web submission for email: {submission.email_id}")
                self.finalize_submission(instance, WebSubmissionConfig(user_email=submission.user, workdir=submission.workdir))
            else:
                fetch_mail_logger.debug(f"Finalizing MinIO submission for email: {submission.email_id}")
                self._handle_instance_for_minio(instance, submission.email_id, submission.workdir, submission.bucket_name)
            fetch_mail_logger.debug(f"Creating mail info for email: {submission.email_id}")
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
            self._handle_common_tasks(instance, email_id, mail_zip, bucket_name="")
            fetch_mail_logger.info(f"Finalized web submission for email_id={email_id}")

    def _get_mail_zip_path(self, workdir: str, email_id: str) -> str:
        return os.path.join(os.path.dirname(workdir), f"{email_id}.tar.gz")

    def _handle_instance_for_minio(self, instance, email_id: str, workdir: str, bucket_name: str):
        """
        Handle post-processing of a MinIO-parsed email instance.
        """
        with safe_execution(f"finalizing MinIO email {email_id}"):
            fetch_mail_logger.debug(f"Extracting reportedBy for MinIO email: {email_id}")
            user_email = self._extract_reported_by_from_user_submission(workdir)
            fetch_mail_logger.debug(f"Extracted reportedBy: {user_email} for email: {email_id}")
            instance.reportedBy = user_email
            fetch_mail_logger.debug(f"Saving instance for MinIO email: {email_id}")
            instance.save()
            fetch_mail_logger.debug(f"Getting mail zip path for MinIO email: {email_id}")
            mail_zip = self._get_mail_zip_path(workdir, email_id)
            fetch_mail_logger.debug(f"Handling common tasks for MinIO email: {email_id}")
            self._handle_common_tasks(instance, email_id, mail_zip, bucket_name)
            fetch_mail_logger.info(f"Finalized MinIO email for email_id={email_id}")

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
        return [f for f in all_files if f.endswith(".eml") and not f.startswith(prefix)]

    def _handle_common_tasks(self, instance, email_id: str, mail_zip: str, bucket_name: str):
        """
        Handle artifacts, attachments, headers, bodies, and case creation.
        """
        user = UserCreationService().get_or_create_user(instance.reportedBy)
        fetch_mail_logger.debug(f"Handling artifacts and attachments for email: {email_id}")
        artifact_ids = Handlers().handle_artifacts(instance)
        fetch_mail_logger.debug(f"Handling attachments for email: {email_id}")
        attachment_result = Handlers().handle_attachments(instance, mail_zip, bucket_name=bucket_name)
        attachment_ids, attachment_id_ai = attachment_result.ids, attachment_result.ai_ids
        fetch_mail_logger.debug(f"Handling mail header for email: {email_id}")
        Handlers().handle_mail_header(instance)
        fetch_mail_logger.debug(f"Handling mail body for email: {email_id}")
        Handlers().handle_mail_body(instance, email_id)
        fetch_mail_logger.debug(f"Creating case for email: {email_id}")

        related_ids = flatten_id_lists(artifact_ids, attachment_ids)
        fetch_mail_logger.debug(f"Related IDs for case creation: {related_ids} for email: {email_id}")
        CaseCreatorService().create_case(CaseInputData(
            instance=instance,
            user=user,
            artifact_ids=related_ids,
            attachment_ids=attachment_ids,
            attachment_ai_ids=attachment_id_ai
        ))
