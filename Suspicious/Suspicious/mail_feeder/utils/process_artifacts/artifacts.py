import logging
import json
from django.db import transaction
from typing import List, Optional

from .models import ArtifactModel, ConfigModel
from .utils import extract_url_info

from mail_feeder.models import (
    ArtifactIsDomain, ArtifactIsHash, ArtifactIsIp,
    ArtifactIsMailAddress, ArtifactIsUrl, MailArtifact
)

from domain_process.domain_utils.domain_handler import DomainHandler
from email_process.email_utils.email_handler import MailAddressHandler
from hash_process.hash_utils.hash_handler import HashHandler
from ip_process.ip_utils.ip_handler import IPHandler
from url_process.url_utils.url_handler import URLHandler
from hash_process.models import Hash
from mail_feeder.utils.email_validation.validators import EmailValidatorService
from mail_feeder.utils.user_creation.creation import UserCreationService

logger = logging.getLogger("tasp.cron.fetch_and_process_emails")

CONFIG_PATH = "/app/settings.json"
with open(CONFIG_PATH) as config_file:
    config = json.load(config_file)

class ArtifactService:
    def __init__(self, company_config: Optional[list[str]] = None):
        self.company_config = config.get('company_domains', None)

    # --- Dispatcher ---
    def handle_artifacts(self, artifacts: List[ArtifactModel], mail_instance) -> None:
        handlers = {
            'mail': self._handle_mail,
            'domain': self._handle_domain,
            'url': self._handle_url,
            'ip': self._handle_ip,
            'hash': self._handle_hash,
        }

        for artifact in artifacts:
            handler = handlers.get(artifact.dataType)
            if not handler:
                logger.warning(f"Unknown artifact type: {artifact.dataType}")
                continue
            try:
                handler(artifact.data, mail_instance)
            except Exception as e:
                logger.error(f"Error processing {artifact.dataType}: {e}")

    # --- Core handlers ---
    def _handle_mail(self, data_value: str, mail_instance):
        data_value = data_value.lower()
        if "email=" in data_value:
            data_value = data_value.split("email=")[-1]
        if MailArtifact.objects.filter(
            mail=mail_instance,
            artifact_type="MailAddress",
            artifactIsMailAddress__mail_address__address=data_value
        ).exists():
            logger.debug(f"Mail {data_value} already linked.")
            return

        handler = MailAddressHandler()
        artifact = handler.handle_mail(data_value)
        if not artifact:
            logger.error(f"Handler failed for mail {data_value}")
            return

        with transaction.atomic():
            mail_artifact = MailArtifact.objects.create(mail=mail_instance, artifact_type="MailAddress")
            validator = EmailValidatorService(ConfigModel(company_domains=self.company_config))
            valid_email = validator.is_company_email(data_value)
            if valid_email.is_valid:
                UserCreationService().get_or_create_user(valid_email.normalized)
            else:
                artifact_mail = ArtifactIsMailAddress.objects.get_or_create(
                    mail_address=artifact, artifact=mail_artifact
                )
                mail_artifact.artifactIsMailAddress = artifact_mail[0]
                mail_artifact.save()
            mail_instance.save()

    def _handle_domain(self, data_value: str, mail_instance):
        data_value = data_value.lower()
        if MailArtifact.objects.filter(
            mail=mail_instance, artifact_type="Domain",
            artifactIsDomain__domain__value=data_value
        ).exists():
            logger.debug(f"Domain {data_value} already linked.")
            return

        handler = DomainHandler()
        artifact = handler.handle_domain(data_value)
        if not artifact:
            logger.error(f"Domain handler failed for {data_value}")
            return

        with transaction.atomic():
            mail_artifact = MailArtifact.objects.create(mail=mail_instance, artifact_type="Domain")
            artifact_domain = ArtifactIsDomain.objects.get_or_create(domain=artifact, artifact=mail_artifact)
            mail_artifact.artifactIsDomain = artifact_domain[0]
            mail_artifact.save()
            mail_instance.save()

    def _handle_url(self, data_value: str, mail_instance):
        urls = {data_value}
        decoded = extract_url_info(data_value)
        if decoded.decoded_url:
            urls.add(decoded.decoded_url)

        for url in urls:
            if not url:
                continue
            if MailArtifact.objects.filter(
                mail=mail_instance, artifact_type="URL",
                artifactIsUrl__url__address=url
            ).exists():
                logger.debug(f"URL {url} already linked.")
                continue
            self._process_url(url, mail_instance)

    def _process_url(self, url: str, mail_instance):
        handler = URLHandler()
        artifact = handler.handle_url(url)
        if not artifact:
            logger.error(f"URL handler failed for {url}")
            return

        with transaction.atomic():
            mail_artifact = MailArtifact.objects.create(mail=mail_instance, artifact_type="URL")
            artifacturl = ArtifactIsUrl.objects.get_or_create(url=artifact[0], artifact=mail_artifact)
            mail_artifact.artifactIsUrl = artifacturl[0]
            mail_artifact.save()
            mail_instance.save()

    def _handle_ip(self, data_value: str, mail_instance):
        if MailArtifact.objects.filter(
            mail=mail_instance, artifact_type="IP",
            artifactIsIp__ip__address=data_value.lower()
        ).exists():
            logger.debug(f"IP {data_value} already linked.")
            return

        handler = IPHandler()
        artifact = handler.handle_ip(data_value)
        if artifact:
            with transaction.atomic():
                mail_artifact = MailArtifact.objects.create(mail=mail_instance, artifact_type="IP")
                artifactip = ArtifactIsIp.objects.get_or_create(ip=artifact, artifact=mail_artifact)
                mail_artifact.artifactIsIp = artifactip[0]
                mail_artifact.save()
                mail_instance.save()

    def _handle_hash(self, data_value: str, mail_instance):
        data_value = data_value.lower()
        if MailArtifact.objects.filter(
            mail=mail_instance, artifact_type="Hash",
            artifactIsHash__hash__value=data_value
        ).exists():
            logger.debug(f"Hash {data_value} already linked.")
            return

        handler = HashHandler()
        artifact = handler.handle_hash(data_value)
        if not artifact:
            logger.error(f"Hash handler failed for {data_value}")
            return

        with transaction.atomic():
            mail_artifact = MailArtifact.objects.create(mail=mail_instance, artifact_type="Hash")
            hash_obj, _ = Hash.objects.get_or_create(value=data_value)
            artifact_hash = ArtifactIsHash.objects.get_or_create(hash=hash_obj, artifact=mail_artifact)
            mail_artifact.artifactIsHash = artifact_hash[0]
            mail_artifact.save()
            mail_instance.save()
