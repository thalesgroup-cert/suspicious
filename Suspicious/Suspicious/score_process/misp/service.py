from .client import MISPClient
from pymisp import  MISPObject
from ip_process.models import IP
from url_process.models import URL
from hash_process.models import Hash
from domain_process.models import Domain
from case_handler.models import Case
from typing import Optional, Any
import logging
from .objects import (build_email_object,
        build_url_object,
        build_ip_object,
        build_hash_object,
        build_domain_object,
        finalize_misp_object)
from .events import MISPEventManager

import json
from .config_loader import load_misp_settings

CONFIG_PATH = "/app/settings.json"
with open(CONFIG_PATH) as config_file:
    config = json.load(config_file)

misp_config = config.get('misp', {})

logger = logging.getLogger('tasp.cron.update_ongoing_case_jobs')


class MISPService:
    def __init__(self, primary: bool = True):
        settings = load_misp_settings()
        config = settings.suspicious if primary else settings.security
        self.client = MISPClient(config=config)
        self.primary = primary

    # ----------------------
    # Case update
    # ----------------------
    def update_misp(self, case: Case) -> None:
        try:
            mem = MISPEventManager(self.client)
            event = mem.get_or_create_event(case)
            if not event or not hasattr(event, 'id'):
                logger.error(f"Could not create or retrieve event for case {case.id}.")
                return

            if case.fileOrMail and hasattr(case.fileOrMail, 'mail'):
                mail = case.fileOrMail.mail
                obj = build_email_object(mail, case.id, case.results)
                self.check_and_update_monthly_misp(obj, case.id, case.results)
                finalize_misp_object(event.id, obj)
                if hasattr(mail, 'mail_attachments'):
                    for attachment in mail.mail_attachments.all():
                        self.add_attachment_object(event.id, attachment, case.id, case.results)

                if hasattr(mail, 'mail_artifacts'):
                    for artifact in mail.mail_artifacts.all():
                        self.add_artifact_object(event.id, artifact, case.id, case.results)

            if hasattr(case, 'nonFileIocs') and case.nonFileIocs:
                ioc_data = case.nonFileIocs.get_iocs()
                for ioc_type, ioc in ioc_data.items():
                    if ioc:
                        self.add_artifact_object(event.id, ioc, case.id, case.results, ioc_type=ioc_type)
        except Exception as e:
            logger.error(f"Error updating MISP for case {case.id}: {e}", exc_info=True)

    def add_artifact_object(self, event_id: str, artifact: Any, case_number: Any, detection_level: str, ioc_type: Optional[str] = None) -> None:
        """
        Add an artifact (URL, IP, hash, domain, email) to a MISP event.

        Args:
            event_id (str): ID of the MISP event.
            artifact: The artifact data.
            case_number: The case number.
            detection_level (str): The detection level.
            ioc_type (Optional[str]): For non-file artifacts, the type (e.g., 'url', 'ip', 'hash').
        """
        try:
            obj = None
            if ioc_type:
                if ioc_type == 'url' and isinstance(artifact, URL):
                    obj = build_url_object(event_id, artifact, case_number)
                elif ioc_type == 'domain' and isinstance(artifact, Domain):
                    obj = build_domain_object(event_id, artifact, case_number)
                elif ioc_type == 'ip' and isinstance(artifact, IP):
                    obj = build_ip_object(event_id, artifact, case_number)
                elif ioc_type == 'hash' and isinstance(artifact, Hash):
                    obj = build_hash_object(event_id, artifact, case_number)
                else:
                    logger.warning(f"[MISPHandler] Unsupported or missing artifact type '{ioc_type}' for case {case_number}. Skipping.")
            else:
                artifact_type = artifact.artifact_type.lower()
                if artifact_type == 'url' and hasattr(artifact, 'artifactIsUrl'):
                    obj = build_url_object(event_id, artifact.artifactIsUrl.url, case_number)
                elif artifact_type == 'ip' and hasattr(artifact, 'artifactIsIp'):
                    obj = build_ip_object(event_id, artifact.artifactIsIp.ip, case_number)
                elif artifact_type == 'hash' and hasattr(artifact, 'artifactIsHash'):
                    obj = build_hash_object(event_id, artifact.artifactIsHash.hash, case_number)
                elif artifact_type == 'domain' and hasattr(artifact, 'artifactIsDomain'):
                    obj = build_domain_object(event_id, artifact.artifactIsDomain.domain, case_number)
                else:
                    logger.warning(f"[MISPHandler] Unsupported or missing artifact type '{artifact_type}' for case {case_number}. Skipping.")
            if not obj:
                return
            self.check_and_update_monthly_misp(obj, case_number, detection_level)
            finalize_misp_object(event_id, obj)

        except Exception as e:
            logger.error(f"[MISPHandler] Error adding artifact to event {event_id}: {e}", exc_info=True)

    def add_attachment_object(self, event_id: str, attachment: Any, case_number: Any, detection_level: str) -> None:
        # Implementation for adding attachment object
        pass

    # ----------------------
    # Secondary monthly MISP
    # ----------------------
    def check_and_update_monthly_misp(self, misp_object: MISPObject, case_number: Any, ioc_level: str) -> None:
        if ioc_level.upper() not in ['MALICIOUS', 'SUSPICIOUS']:
            return
        try:
            secondary_handler = MISPService(primary=False)
            mem = MISPEventManager(secondary_handler.client)
            monthly_event = mem.get_or_create_monthly_event()
            new_obj = MISPObject(misp_object.name)
            for attr in misp_object.attributes:
                if attr.object_relation and attr.value:
                    attr_type = attr.type if getattr(attr, 'type', None) else attr.object_relation
                    new_obj.add_attribute(attr.object_relation, type=attr_type, value=attr.value)
            secondary_handler.finalize_misp_object(monthly_event['Event']['id'], new_obj, case_number, ioc_level)
        except Exception as e:
            logger.error(f"Error updating monthly event in secondary MISP for case {case_number}: {e}", exc_info=True)
