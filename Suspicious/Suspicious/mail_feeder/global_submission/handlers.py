import os
from dataclasses import dataclass, field
from typing import Any, Optional, List
import logging
from mail_feeder.models import MailArchive, MailArtifact, MailAttachment
from mail_feeder.job_handler.artifacts.artifacts import ArtifactJobLauncherService
from mail_feeder.job_handler.attachments.attachments import AttachmentJobLauncherService
from file_process.file_utils.file_handler import FileHandler

from .utils import safe_execution

WORKDIR="/tmp/mail_feeder_global_submission"
fetch_mail_logger = logging.getLogger("tasp.cron.fetch_and_process_emails")


@dataclass
class AttachmentDispatchResult:
    services: List[AttachmentJobLauncherService] = field(default_factory=list)
    ai_archive: Optional[Any] = None


class Handlers:
    """
    Handlers for artifacts, attachments, mail headers, and mail bodies.
    """
    def handle_artifacts(self, instance) -> ArtifactJobLauncherService:
        fetch_mail_logger.debug(f"Handling artifacts for mail ID: {instance.mail_id}")
        artifact_handler = ArtifactJobLauncherService()
        fetch_mail_logger.debug("Initialized ArtifactJobLauncherService")
        with safe_execution("handling artifacts"):
            fetch_mail_logger.debug("Processing artifacts")
            instance_artifacts = list(MailArtifact.objects.filter(mail=instance))
            fetch_mail_logger.debug(f"Artifacts to process: {len(instance_artifacts)}")
            if instance_artifacts:
                fetch_mail_logger.debug("Launching artifact processing")
                artifact_handler.process_artifacts(instance_artifacts)
                fetch_mail_logger.debug("Artifact processing completed (intents queued)")
        return artifact_handler

    def handle_attachments(self, instance, mail_zip: Optional[str], bucket_name: Optional[str] = None) -> AttachmentDispatchResult:
        result = AttachmentDispatchResult()

        instance_attachments = MailAttachment.objects.filter(mail=instance)
        for att in instance_attachments:
            if att:
                with safe_execution("processing attachment"):
                    fetch_mail_logger.debug(f"Processing attachment ID: {att.id} for mail ID: {instance.mail_id}")
                    attachment_handler = AttachmentJobLauncherService()
                    service, _ = attachment_handler.process_attachment(att.file)
                    result.services.append(service)
        fetch_mail_logger.debug(f"Completed processing attachments for mail ID: {instance.mail_id}")
        if mail_zip:
            fetch_mail_logger.debug(f"Processing mail archive for mail ID: {instance.mail_id}")
            mail_archive = MailArchive.objects.filter(mail=instance).first()
            if not mail_archive:
                fetch_mail_logger.debug(f"Creating mail archive for mail ID: {instance.mail_id}")
                archive, _ = FileHandler.handle_file(file=None, mail=mail_zip)
                if archive is None:
                    fetch_mail_logger.warning(
                        f"Skipping mail archive for mail ID {instance.mail_id}: "
                        f"could not load file from {mail_zip}"
                    )
                    return result
                mail_archive = MailArchive.objects.create(mail=instance, archive=archive, bucket_name=bucket_name)

            if mail_archive.archive is None:
                fetch_mail_logger.info(
                    f"Mail archive {mail_archive.id} has no file attached; skipping Cortex AI"
                )
            else:
                result.ai_archive = mail_archive

        return result

    def handle_mail_header(self, instance) -> list[tuple]:
        if hasattr(instance, "mail_header") and instance.mail_header:
            return [(instance.mail_header, "mail_header")]
        return []

    def handle_mail_body(self, instance, email_id) -> list[tuple]:
        intents = []
        if hasattr(instance, "mail_body") and instance.mail_body:
            with safe_execution("handling mail body"):
                email_dir = os.path.join(WORKDIR, email_id)
                os.makedirs(email_dir, exist_ok=True)
                file_path = os.path.join(email_dir, f"{instance.mail_body.fuzzy_hash}.txt")
                with open(file_path, "w") as f:
                    f.write(instance.mail_body.body_value)
                intents.append((file_path, "mail_body"))
        return intents
