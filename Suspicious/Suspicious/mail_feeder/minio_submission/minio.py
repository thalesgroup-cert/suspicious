import os
import email
import logging
from typing import List, Optional
from .models import MinioEmailData

from mail_feeder.global_submission.gsubmission import GlobalSubmissionService as glo
from mail_feeder.global_submission.models import MailSubmissionData

from minio_submissions.utils import safe_execution, extract_email_address

fetch_mail_logger = logging.getLogger("tasp.cron.fetch_and_process_emails")
logger = logging.getLogger(__name__)


class MinioEmailService:
    """
    Service for processing emails from MinIO work directories.
    """

    def __init__(self, email_handler=None):
        self.email_handler = email_handler  # Optionally inject an email handler service

    def process_emails_from_minio_workdir(self, workdir: str):
        """
        Process all regular emails in a given MinIO work directory.
        """
        email_id = os.path.basename(workdir)
        with safe_execution(f"processing MinIO emails {email_id}"):
            fetch_mail_logger.info(f"Processing MinIO emails in {workdir}")
            eml_files = glo.list_eml_files(workdir, exclude_prefix="user_submission")
            for filename in eml_files:
                fetch_mail_logger.debug(f"Processing MinIO email file {filename}")
                glo.process_single_email(MailSubmissionData(
                    workdir=workdir,
                    filename=filename,
                    email_id=email_id,
                    user=None,
                    is_submitted=False
                ))

    def _handle_instance_for_minio(self, instance, email_id: str, workdir: str):
        """
        Handle post-processing of a MinIO-parsed email instance.
        """
        with safe_execution(f"finalizing MinIO email {email_id}"):
            user_email = self._extract_reported_by_from_user_submission(workdir)
            instance.reportedBy = user_email
            instance.save()

            mail_zip = glo._get_mail_zip_path(workdir, email_id)
            glo._handle_common_instance_tasks(instance, email_id, mail_zip)

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
