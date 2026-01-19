import os
from typing import Optional
import logging
from mail_feeder.models import MailArchive, MailArtifact, MailAttachment
from mail_feeder.job_handler.artifacts.artifacts import ArtifactJobLauncherService
from mail_feeder.job_handler.attachments.attachments import AttachmentJobLauncherService
from cortex_job.cortex_utils.cortex_and_job_management import CortexJob
from file_process.file_utils.file_handler import FileHandler

from .models import ArtifactResult
from .utils import safe_execution

WORKDIR="/tmp/mail_feeder_global_submission"
fetch_mail_logger = logging.getLogger("tasp.cron.fetch_and_process_emails")

class Handlers:
    """
    Handlers for artifacts, attachments, mail headers, and mail bodies.
    """
    def handle_artifacts(self, instance) -> list[int]:
        fetch_mail_logger.debug(f"Handling artifacts for mail ID: {instance.mail_id}")
        artifact_handler = ArtifactJobLauncherService()
        fetch_mail_logger.debug("Initialized ArtifactJobLauncherService")
        instance_artifacts = MailArtifact.objects.filter(mail=instance)
        fetch_mail_logger.debug(f"Found {instance_artifacts.count()} artifacts for mail ID: {instance.mail_id}")
        artifact_ids = []
        fetch_mail_logger.debug("Starting artifact processing")
        with safe_execution("handling artifacts"):
            fetch_mail_logger.debug("Processing artifacts")
            instance_artifacts = list(MailArtifact.objects.filter(mail=instance))
            fetch_mail_logger.debug(f"Artifacts to process: {len(instance_artifacts)}")
            if instance_artifacts:
                fetch_mail_logger.debug("Launching artifact processing")
                artifact_ids = artifact_handler.process_artifacts(instance_artifacts)

                fetch_mail_logger.debug(f"Artifact processing completed with IDs: {artifact_ids}")
        return artifact_ids

    def handle_attachments(self, instance, mail_zip: Optional[str], bucket_name: Optional[str] = None) -> ArtifactResult:
        attachment_handler = AttachmentJobLauncherService()
        attachment_ids: list[int] = []
        attachment_id_ai: list[int] = []

        instance_attachments = MailAttachment.objects.filter(mail=instance)
        for att in instance_attachments:
            if att:
                with safe_execution("processing attachment"):
                    fetch_mail_logger.debug(f"Processing attachment ID: {att.id} for mail ID: {instance.mail_id}")
                    ids, id_ai = attachment_handler.process_attachment(att.file)
                    if ids:
                        attachment_ids.extend(str(i) for i in ids)
                    if id_ai:
                        attachment_id_ai.append(str(id_ai))
        fetch_mail_logger.debug(f"Completed processing attachments for mail ID: {instance.mail_id}")
        # Process archive
        if mail_zip:
            fetch_mail_logger.debug(f"Processing mail archive for mail ID: {instance.mail_id}")
            mail_archive = MailArchive.objects.filter(mail=instance).first()
            if not mail_archive:
                fetch_mail_logger.debug(f"Creating mail archive for mail ID: {instance.mail_id}")
                archive, _ = FileHandler.handle_file(file=None, mail=mail_zip)
                mail_archive = MailArchive.objects.create(mail=instance, archive=archive, bucket_name=bucket_name)

            with safe_execution("launching cortex AI jobs"):
                cortex_job = CortexJob()
                fetch_mail_logger.debug(f"Launching Cortex AI jobs for mail archive ID: {mail_archive.id}")
                id_ai = cortex_job.launch_cortex_ai_jobs(mail_archive, "file")
                if id_ai:
                    fetch_mail_logger.debug(f"Received AI ID: {id_ai} for mail archive ID: {mail_archive.id}")
                    attachment_id_ai.append(str(id_ai))

        return ArtifactResult(ids=attachment_ids, ai_ids=attachment_id_ai)

    def handle_mail_header(self, instance):
        if hasattr(instance, "mail_header") and instance.mail_header:
            with safe_execution("handling mail header"):
                handler = CortexJob()
                handler.launch_cortex_jobs(instance.mail_header, "mail_header")

    def handle_mail_body(self, instance, email_id):
        if hasattr(instance, "mail_body") and instance.mail_body:
            with safe_execution("handling mail body"):
                email_dir = os.path.join(WORKDIR, email_id)
                os.makedirs(email_dir, exist_ok=True)
                file_path = os.path.join(email_dir, f"{instance.mail_body.fuzzy_hash}.txt")
                with open(file_path, "w") as f:
                    f.write(instance.mail_body.body_value)
                handler = CortexJob()
                handler.launch_cortex_jobs(file_path, "mail_body")
