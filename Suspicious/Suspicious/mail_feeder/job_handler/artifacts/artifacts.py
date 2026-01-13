import logging
from typing import List
from pydantic import ValidationError

from .models import ArtifactModel
from .utils import safe_execution
from cortex_job.cortex_utils.cortex_and_job_management import CortexJob
from settings.models import AllowListFile, AllowListDomain
from url_process.url_utils.url_handler import URLHandler

fetch_mail_logger = logging.getLogger("tasp.cron.fetch_and_process_emails")


class ArtifactJobLauncherService:
    """
    Service to launch Cortex jobs for various artifact types.
    """

    def __init__(self):
        self.launched_job_ids: List[int] = []

    def process_artifacts(self, artifacts: list) -> List[int]:
        """
        Validate artifacts and dispatch them to the correct handler.
        Returns a list of launched job IDs.
        """
        handlers = {
            "IP": self._process_ip_artifact,
            "Hash": self._process_hash_artifact,
            "URL": self._process_url_artifact,
            "Domain": self._process_domain_artifact,
            "MailAddress": self._process_mail_artifact,
        }
        for artifact in artifacts:
            try:
                artifact_data = ArtifactModel(artifact_type=artifact.artifact_type)
            except ValidationError as e:
                fetch_mail_logger.error(f"Artifact validation failed: {e}")
                continue

            handler = handlers.get(artifact_data.artifact_type)
            if handler:
                with safe_execution(f"processing {artifact_data.artifact_type} artifact"):
                    handler(artifact)
            else:
                fetch_mail_logger.warning(f"No handler for artifact type {artifact_data.artifact_type}")

        return self.launched_job_ids

    def _process_ip_artifact(self, artifact):
        if artifact.artifactIsIp:
            ip_obj = artifact.artifactIsIp.ip
            fetch_mail_logger.info(f"Processing IP: {ip_obj.address}")
            self._launch_cortex_jobs(ip_obj, "ip")

    def _process_hash_artifact(self, artifact):
        if artifact.artifactIsHash:
            hash_obj = artifact.artifactIsHash.hash
            if self._is_hash_allow_listed(hash_obj):
                return
            self._launch_cortex_jobs(hash_obj, "hash")

    def _process_url_artifact(self, artifact):
        if artifact.artifactIsUrl:
            url_obj = artifact.artifactIsUrl.url
            domain_str = URLHandler().get_domain(url_obj.address)
            if not domain_str:
                fetch_mail_logger.warning(f"Invalid URL: {url_obj.address}")
                return

            from domain_process.models import Domain  # lazy import
            domain_instance = Domain.objects.filter(value=domain_str).first()

            if not self._is_domain_allow_listed(domain_instance, url_obj):
                self._launch_cortex_jobs(url_obj, "url")
            url_obj.save()

    def _process_domain_artifact(self, artifact):
        if artifact.artifactIsDomain:
            domain_obj = artifact.artifactIsDomain.domain
            if not self._is_domain_allow_listed(domain_obj):
                self._launch_cortex_jobs(domain_obj, "domain")
            domain_obj.save()

    def _process_mail_artifact(self, artifact):
        if artifact.artifactIsMailAddress:
            mail_obj = artifact.artifactIsMailAddress.mail_address
            if mail_obj.is_internal:
                fetch_mail_logger.warning(f"Mail address is internal: {mail_obj.address}")
                return
            from email_process.email_utils.email_handler import get_domain, _create_or_update_domain
            domain_str = get_domain(mail_obj)
            domain_instance = _create_or_update_domain(domain_str)
            if not self._is_domain_allow_listed(domain_instance, mail_obj):
                self._launch_cortex_jobs(mail_obj, "mail")
            mail_obj.save()

    def _launch_cortex_jobs(self, obj, artifact_type: str):
        """
        Launch Cortex jobs for the given object and artifact type.
        """
        try:
            self.launched_job_ids += CortexJob().launch_cortex_jobs(obj, artifact_type)
        except Exception as e:
            fetch_mail_logger.error(f"Failed to launch Cortex jobs for {artifact_type}: {e}")

    def _is_hash_allow_listed(self, hash_obj) -> bool:
        """
        Checks if a hash is allow-listed. Updates its IOC attributes if it is.
        """
        if hasattr(hash_obj, "linked_file_hash") and AllowListFile.objects.filter(linked_file_hash=hash_obj).exists():
            fetch_mail_logger.info(f"Hash {hash_obj} is allow-listed")
            hash_obj.ioc_score = 0
            hash_obj.ioc_confidence = 100
            hash_obj.ioc_level = "SAFE-ALLOW_LISTED"
            hash_obj.save()
            return True
        return False

    def _is_domain_allow_listed(self, domain_obj, related_obj=None) -> bool:
        """
        Checks if a domain is allow-listed. Updates its and optionally related object's IOC attributes if it is.
        """
        if domain_obj and AllowListDomain.objects.filter(domain=domain_obj).exists():
            fetch_mail_logger.info(f"Domain {domain_obj} is allow-listed")
            domain_obj.ioc_score = 0
            domain_obj.ioc_confidence = 100
            domain_obj.ioc_level = "SAFE-ALLOW_LISTED"
            domain_obj.save()

            if related_obj:
                related_obj.ioc_score = 0
                related_obj.ioc_confidence = 100
                related_obj.ioc_level = "SAFE-ALLOW_LISTED"
                related_obj.save()
            return True
        return False
