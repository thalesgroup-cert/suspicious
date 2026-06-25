import os
import email
import logging
from typing import Optional

from mail_feeder.web_submission.models import WebSubmissionConfig

from mail_feeder.case_creator.creator import CaseCreatorService
from mail_feeder.case_creator.models import CaseInputData

from mail_feeder.email_handler.email_handler import EmailHandlerService

from mail_feeder.email_info.email_info import MailInfoService

from mail_feeder.utils.user_creation.creation import UserCreationService

from cortex_job.cortex_utils.cortex_and_job_management import CortexJob

from .models import MailSubmissionData
from .utils import safe_execution, extract_email_address
from .handlers import Handlers


fetch_mail_logger = logging.getLogger("tasp.cron.fetch_and_process_emails")

class GlobalSubmissionService:
    """
    Service for processing global email submissions, including artifacts, attachments,
    mail headers, and mail bodies.
    """
    def process_single_email(self, submission: MailSubmissionData):
        with safe_execution(f"processing email {submission.email_id}"):
            from mail_feeder.global_submission.fast_metadata import load_email_data
            mail_instance = load_email_data(
                submission.workdir,
                submission.filename,
                submission.email_id,
                getattr(submission, "reported_by", "") or "",
            )

            instance = EmailHandlerService().handle_mail(
                mail_instance,
                submission.workdir,
                source_filename=submission.filename,
            )

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

        Opens the file in binary mode and parses with
        ``email.message_from_binary_file`` so non-UTF-8 payloads (e.g.
        ISO-8859-1 French content) do not blow up on a default-encoding
        decode in the text reader.
        """
        path = os.path.join(workdir, "user_submission.eml")
        with safe_execution("extracting reportedBy"):
            with open(path, "rb") as f:
                user_submission = email.message_from_binary_file(f)
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
        Collects dispatch intents first, creates the Case, then replays intents
        with case= so CaseAnalyzerJob rows have a valid FK.
        """

        user = UserCreationService().get_or_create_user(instance.reportedBy)
        if user is None:
            fetch_mail_logger.warning(
                "Could not resolve user for mail %s; falling back to system default", instance.mail_id
            )
            user = UserCreationService().create_default_user()

        handlers = Handlers()
        fetch_mail_logger.debug(f"Handling artifacts for email: {email_id}")
        artifact_service = handlers.handle_artifacts(instance)
        fetch_mail_logger.debug(f"Handling attachments for email: {email_id}")
        attachment_result = handlers.handle_attachments(instance, mail_zip, bucket_name=bucket_name)
        fetch_mail_logger.debug(f"Handling mail header for email: {email_id}")
        header_intents = handlers.handle_mail_header(instance)
        fetch_mail_logger.debug(f"Handling mail body for email: {email_id}")
        body_intents = handlers.handle_mail_body(instance, email_id)

        fetch_mail_logger.debug(f"Creating case for email: {email_id}")
        # Create case BEFORE Cortex dispatch so CaseAnalyzerJob rows have a valid FK.
        case = CaseCreatorService().create_case(CaseInputData(
            instance=instance,
            user=user,
            artifact_ids=[],
            attachment_ids=[],
            attachment_ai_ids=[],
        ))
        if case is None:
            fetch_mail_logger.error("Case creation failed for email %s; skipping dispatch", email_id)
            return

        # Replay all queued dispatch intents with the new case.
        artifact_service.dispatch_pending(case)
        for service in attachment_result.services:
            service.dispatch_pending(case)
        cortex = CortexJob()
        for value, data_type in header_intents + body_intents:
            try:
                cortex.launch_cortex_jobs(value=value, data_type=data_type, case=case)
            except Exception:
                fetch_mail_logger.exception(
                    "Failed to launch Cortex jobs (case=%s data_type=%s)",
                    getattr(case, "id", None),
                    data_type,
                )
        if attachment_result.ai_archive is not None:
            try:
                cortex.launch_cortex_ai_jobs(attachment_result.ai_archive, "file", case=case)
            except Exception:
                fetch_mail_logger.exception(
                    "Failed to launch Cortex AI job (case=%s)",
                    getattr(case, "id", None),
                )
