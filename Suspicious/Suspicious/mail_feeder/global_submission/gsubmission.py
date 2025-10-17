import os
import email
import logging
from typing import Optional, Tuple

from mail_feeder.models import MailArchive, MailArtifact, MailAttachment
from mail_feeder.job_handler.artifacts.artifacts import ArtifactJobLauncherService
from mail_feeder.job_handler.attachments.attachments import AttachmentJobLauncherService
from cortex_job.cortex_utils.cortex_and_job_management import CortexJob
from file_process.file_utils.file_handler import FileHandler

from Suspicious.Suspicious.mail_feeder.email_parser.parser import parse_email
from mail_feeder.web_submission.web import WebSubmissionService
from mail_feeder.web_submission.models import WebSubmissionConfig

from mail_feeder.minio_submission.minio import MinioEmailService
from mail_feeder.mail_utils.mail_handler import MailHandler

from mail_feeder.case_creator.creator import CaseCreationService
from mail_feeder.case_creator.models import CaseInputData

from mail_feeder.email_handler.email_handler import EmailHandlerService

from mail_feeder.email_info.email_info import MailInfoService

from mail_feeder.utils.user_creation.creation import UserCreationService


from .models import MailSubmissionData, ArtifactResult
from .utils import safe_execution, flatten_id_lists


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
                WebSubmissionService().finalize_submission(instance, WebSubmissionConfig(user_email=submission.user, workdir=submission.workdir))
            else:
                MinioEmailService()._handle_instance_for_minio(instance, submission.email_id, submission.workdir)
            
            MailInfoService().create_mail_info(instance)
            return instance

    def _get_mail_zip_path(self, workdir: str, email_id: str) -> str:
        return os.path.join(os.path.dirname(workdir), f"{email_id}.tar.gz")

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

        artifact_ids = self.handle_artifacts(instance)
        attachment_result = self.handle_attachments(instance, mail_zip)
        attachment_ids, attachment_id_ai = attachment_result.ids, attachment_result.ai_ids

        self.handle_mail_header(instance)
        self.handle_mail_body(instance, email_id)

        related_ids = flatten_id_lists(artifact_ids, attachment_ids)
        CaseCreationService().create_case(CaseInputData(
            mail_instance=instance,
            user=user,
            artifact_ids=related_ids,
            attachment_ids=attachment_ids,
            attachment_ai_ids=attachment_id_ai
        ))

    def handle_artifacts(self, instance) -> list[int]:
        artifact_handler = ArtifactJobLauncherService()
        instance_artifacts = MailArtifact.objects.filter(mail=instance)
        artifact_ids = []
        with safe_execution("handling artifacts"):
            if instance_artifacts:
                artifact_ids = artifact_handler.process_artifacts(instance_artifacts)
        return artifact_ids

    def handle_attachments(self, instance, mail_zip: Optional[str]) -> ArtifactResult:
        attachment_handler = AttachmentJobLauncherService()
        attachment_ids: list[int] = []
        attachment_id_ai: list[int] = []

        instance_attachments = MailAttachment.objects.filter(mail=instance)
        for att in instance_attachments:
            if att:
                with safe_execution("processing attachment"):
                    ids, id_ai = attachment_handler.process_attachment(att)
                    if ids:
                        attachment_ids.append(ids)
                    if id_ai:
                        attachment_id_ai.append(id_ai)

        # Process archive
        if mail_zip:
            mail_archive = MailArchive.objects.filter(mail=instance).first()
            if not mail_archive:
                archive, _ = FileHandler.handle_file(file=None, mail=mail_zip)
                mail_archive = MailArchive.objects.create(mail=instance, archive=archive)

            with safe_execution("launching cortex AI jobs"):
                cortex_job = CortexJob()
                id_ai = cortex_job.launch_cortex_ai_jobs(mail_archive, "file")
                if id_ai:
                    attachment_id_ai.append(id_ai)

        return ArtifactResult(ids=attachment_ids, ai_ids=attachment_id_ai)

    def handle_mail_header(self, instance):
        if hasattr(instance, "mail_header") and instance.mail_header:
            with safe_execution("handling mail header"):
                handler = CortexJob()
                handler.launch_cortex_jobs(instance.mail_header, "mail_header")

    def handle_mail_body(self, instance, email_id):
        if hasattr(instance, "mail_body") and instance.mail_body:
            with safe_execution("handling mail body"):
                email_dir = os.path.join(self.email_handler.workdir, email_id)
                os.makedirs(email_dir, exist_ok=True)
                file_path = os.path.join(email_dir, f"{instance.mail_body.fuzzy_hash}.txt")
                with open(file_path, "w") as f:
                    f.write(instance.mail_body.body_value)
                handler = CortexJob()
                handler.launch_cortex_jobs(file_path, "mail_body")
