import os
import logging

from mail_feeder.global_submission.gsubmission import GlobalSubmissionService as glo
from mail_feeder.global_submission.models import MailSubmissionData

from .utils import safe_execution

fetch_mail_logger = logging.getLogger("tasp.cron.fetch_and_process_emails")
logger = logging.getLogger(__name__)


class MinioEmailService:
    """
    Service for processing emails from MinIO work directories.
    """

    def __init__(self, email_handler=None):
        self.email_handler = email_handler  # Optionally inject an email handler service

    def process_emails_from_minio_workdir(self, workdir: str, bucket_name: str) -> None:
        """
        Process all regular emails in a given MinIO work directory.
        """
        email_id = os.path.basename(workdir)
        with safe_execution(f"processing MinIO emails {email_id}"):
            fetch_mail_logger.info(f"Processing MinIO emails in {workdir}")
            eml_files = glo().list_eml_files(workdir=workdir, prefix="user_submission")
            for filename in eml_files:
                fetch_mail_logger.debug(f"Processing MinIO email file {filename}")
                glo().process_single_email(MailSubmissionData(
                    workdir=workdir,
                    filename=filename,
                    email_id=email_id,
                    user=None,
                    bucket_name=bucket_name,
                    is_submitted=False
                ))

