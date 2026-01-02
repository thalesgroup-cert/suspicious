import logging
import os
from mail_feeder.global_submission.gsubmission import GlobalSubmissionService as glo
from mail_feeder.global_submission.models import MailSubmissionData

from .models import WebSubmissionConfig
from .utils import safe_execution

logger = logging.getLogger("tasp.cron.fetch_and_process_emails")

class WebSubmissionService:
    """
    Service to process emails submitted via web forms.
    """

    def __init__(self):
        self.logger = logger

    def process_emails(self, config: WebSubmissionConfig):
        """
        Process all emails in the working directory for the given user.
        Returns the last processed mail instance or None if processing failed.
        """
        email_id = os.path.basename(config.workdir)
        last_instance = None

        with safe_execution(f"processing emails in {config.workdir}"):
            self.logger.info(f"Processing submitted emails in {config.workdir}")
            eml_files = glo().list_eml_files(config.workdir, prefix="user_submission")
            for filename in eml_files:
                self.logger.debug(f"Processing email file: {filename}")
                last_instance = glo().process_single_email(MailSubmissionData(
                    workdir=config.workdir,
                    filename=filename,
                    email_id=email_id,
                    user=config.user_email,
                    is_submitted=True
                ))
        return last_instance


