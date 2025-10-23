import os
from typing import Optional

from mail_feeder.models import MailArchive, MailArtifact, MailAttachment
from mail_feeder.job_handler.artifacts.artifacts import ArtifactJobLauncherService
from mail_feeder.job_handler.attachments.attachments import AttachmentJobLauncherService
from cortex_job.cortex_utils.cortex_and_job_management import CortexJob
from file_process.file_utils.file_handler import FileHandler

from .models import ArtifactResult
from .utils import safe_execution

WORKDIR="/tmp/mail_feeder_global_submission"

class Handlers:
    """
    Handlers for artifacts, attachments, mail headers, and mail bodies.
    """
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
                email_dir = os.path.join(WORKDIR, email_id)
                os.makedirs(email_dir, exist_ok=True)
                file_path = os.path.join(email_dir, f"{instance.mail_body.fuzzy_hash}.txt")
                with open(file_path, "w") as f:
                    f.write(instance.mail_body.body_value)
                handler = CortexJob()
                handler.launch_cortex_jobs(file_path, "mail_body")
