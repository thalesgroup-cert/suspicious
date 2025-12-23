from .client import MISPClient
from .utils import current_month_event_name, first_day_of_month
from score_process.scoring.header_parser import parse_email_headers
from pymisp import MISPEvent, MISPObject
from ip_process.models import IP
from url_process.models import URL
from hash_process.models import Hash
from domain_process.models import Domain
from case_handler.models import Case
from typing import Optional, Any
import logging
from datetime import datetime
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
    # Event retrieval/creation
    # ----------------------
    def get_or_create_event_for_email(self, case: Case) -> Optional[MISPEvent]:
        event_name = f"Email Analysis - Case {case.id}"
        try:
            event_id = self._find_event_by_name(event_name)
            if event_id:
                logger.info(f"Found existing event {event_id} for {event_name}")
                event_data = self.client.misp.get_event(event_id)
                self.add_case_number_attribute(event_data['Event'], case.id)
                event_obj = MISPEvent().load(event_data['Event'])
                detection_tag = self.get_detection_level_tag(case.results)
                if detection_tag:
                    event_obj.add_tag(detection_tag)
                self.client.misp.update_event(event_obj)
                return event_obj

            # Create new event
            event = MISPEvent()
            event.info = event_name
            event.date = datetime.now().strftime("%Y-%m-%d")
            event.distribution = 0
            event.threat_level_id = 3
            event.analysis = 1
            created_event = self.client.misp.add_event(event)
            if 'Event' in created_event and 'id' in created_event['Event']:
                self.add_case_number_attribute(created_event['Event'], case.id)
                event_obj = MISPEvent().load(created_event['Event'])
                detection_tag = self.get_detection_level_tag(case.results)
                if detection_tag:
                    event_obj.add_tag(detection_tag)
                self.client.misp.update_event(event_obj)
                return event_obj
            return None
        except Exception as e:
            logger.error(f"Error processing event for {event_name}: {e}", exc_info=True)
            return None

    def get_or_create_monthly_event(self) -> Optional[MISPEvent]:
        event_name = current_month_event_name()
        event_date = first_day_of_month()
        tags_config = misp_config.get('tags', {})

        try:
            event_id = self._find_event_by_name(event_name)
            if event_id:
                logger.info(f"Found existing monthly event {event_id} for {event_name}")
                event = self.client.misp.get_event(event_id, pythonify=True)
                if event:
                    tags = self.parse_tags(tags_config)
                    for tag in tags:
                        event.add_tag(tag["name"])
                    return self.client.misp.update_event(event, pythonify=True)
                return None

            # Create new monthly event
            event = MISPEvent()
            event.info = event_name
            event.date = event_date
            event.distribution = 3
            event.threat_level_id = 3
            event.analysis = 1

            tags = self.parse_tags(tags_config)
            for tag in tags:
                event.add_tag(tag["name"])

            created = self.client.misp.add_event(event, pythonify=True)
            return created
        except Exception as e:
            logger.error(f"Error creating or retrieving monthly event: {e}", exc_info=True)
            return None

    def parse_tags(self, tags_config):
        """
        Parse tags from configuration and return a list of tag dictionaries.
        Args:
        tags_config (dict): Configuration dictionary for tags.
        Returns:
        list: List of tag dictionaries.
        """
        tags = []
        for key, value in tags_config.items():
            if isinstance(value, str):
                for tag in value.split(','):
                    tag = tag.strip()
                    if key == "other":
                        tags.append({"name": tag})
                    else:
                        tags.append({"name": f"{key}:{tag}"})
            elif isinstance(value, dict):
                for subkey, subval in value.items():
                    tags.append({"name": f'{key}:{subkey}="{subval}"'})
        return tags

    # ----------------------
    # Case update
    # ----------------------
    def update_misp(self, case: Case) -> None:
        try:
            event = self.get_or_create_event_for_email(case)
            if not event or not hasattr(event, 'id'):
                logger.error(f"Could not create or retrieve event for case {case.id}.")
                return

            if case.fileOrMail and hasattr(case.fileOrMail, 'mail'):
                mail = case.fileOrMail.mail
                self.add_email_object(event.id, mail, case.id, case.results)

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

    # ----------------------
    # Secondary monthly MISP
    # ----------------------
    def check_and_update_monthly_misp(self, misp_object: MISPObject, case_number: Any, ioc_level: str) -> None:
        if ioc_level.upper() not in ['MALICIOUS', 'SUSPICIOUS']:
            return
        try:
            secondary_handler = MISPService(MISPClient, primary=False)
            monthly_event = secondary_handler.get_or_create_monthly_event()
            new_obj = MISPObject(misp_object.name)
            for attr in misp_object.attributes:
                if attr.object_relation and attr.value:
                    attr_type = attr.type if getattr(attr, 'type', None) else attr.object_relation
                    new_obj.add_attribute(attr.object_relation, type=attr_type, value=attr.value)
            secondary_handler.finalize_misp_object(monthly_event['Event']['id'], new_obj, case_number, ioc_level)
        except Exception as e:
            logger.error(f"Error updating monthly event in secondary MISP for case {case_number}: {e}", exc_info=True)

    # ----------------------
    # Attribute helpers
    # ----------------------
    def add_case_number_attribute(self, event: dict, case_number: Any) -> None:
        case_number_attribute = {
            'type': 'text',
            'value': str(case_number),
            'category': 'Other',
            'comment': 'Case Number'
        }
        self.client.misp.add_attribute(event['id'], case_number_attribute)

    # ----------------------
    # Email / Artifacts
    # ----------------------
    def add_email_object(self, event_id: str, mail: Any, case_number: Any, detection_level: str) -> None:
        """
        Add an email object to a MISP event.

        Args:
            event_id (str): ID of the MISP event.
            mail: Email object containing header and content details.
            case_number: The case number.
            detection_level (str): Detection level for tagging.
        """
        logger.debug(f"[MISPHandler] Adding email object for case {case_number}.")
        try:
            parsed_headers = parse_email_headers(mail.mail_header.header_value)
            cleaned_subject = mail.subject.replace("\n", " ").replace("\r", "")
            misp_object = MISPObject('email')
            misp_object.comment = f"Case: {case_number}, Detection level: {detection_level}"

            misp_object.add_attribute('from', value=parsed_headers.get('from', ''))
            misp_object.add_attribute('from-display-name', value=parsed_headers.get('from_display_name', ''))
            misp_object.add_attribute('to', value=parsed_headers.get('to', ''))
            misp_object.add_attribute('to-display-name', value=parsed_headers.get('to_display_name', ''))
            misp_object.add_attribute('cc', value=parsed_headers.get('cc', ''))
            misp_object.add_attribute('subject', value=cleaned_subject)
            misp_object.add_attribute('reply-to', value=parsed_headers.get('reply_to', ''))
            misp_object.add_attribute('return-path', value=parsed_headers.get('return_path', ''))
            misp_object.add_attribute('user-agent', value=parsed_headers.get('user_agent', ''))
            misp_object.add_attribute('send-date', value=parsed_headers.get('send_date', ''))

            response = self.misp.add_object(event_id, misp_object)
            logger.info(f"[MISPHandler] Added email object to event {event_id} for case {case_number}. Response: {response}")
        except Exception as e:
            logger.error(f"[MISPHandler] Error adding email object for case {case_number}: {e}", exc_info=True)

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
                if ioc_type:
                    if ioc_type == 'url' and isinstance(artifact, URL):
                        self.add_url_artifact(event_id, artifact, case_number)
                    elif ioc_type == 'ip' and isinstance(artifact, IP):
                        self.add_ip_artifact(event_id, artifact, case_number)
                    elif ioc_type == 'hash' and isinstance(artifact, Hash):
                        self.add_hash_artifact(event_id, artifact, case_number)
                    else:
                        logger.warning(f"[MISPHandler] Unsupported or missing artifact type '{ioc_type}' for case {case_number}. Skipping.")
                else:
                    artifact_type = artifact.artifact_type.lower()
                    if artifact_type == 'url' and hasattr(artifact, 'artifactIsUrl'):
                        self.add_url_artifact(event_id, artifact.artifactIsUrl.url, case_number)
                    elif artifact_type == 'ip' and hasattr(artifact, 'artifactIsIp'):
                        self.add_ip_artifact(event_id, artifact.artifactIsIp.ip, case_number)
                    elif artifact_type == 'hash' and hasattr(artifact, 'artifactIsHash'):
                        self.add_hash_artifact(event_id, artifact.artifactIsHash.hash, case_number)
                    elif artifact_type == 'domain' and hasattr(artifact, 'artifactIsDomain'):
                        self.add_domain_artifact(event_id, artifact.artifactIsDomain.domain, case_number)
                    else:
                        logger.warning(f"[MISPHandler] Unsupported or missing artifact type '{artifact_type}' for case {case_number}. Skipping.")
            except Exception as e:
                logger.error(f"[MISPHandler] Error adding artifact to event {event_id}: {e}", exc_info=True)

    def add_url_artifact(self, event_id: str, artifact: URL, case_number: Any) -> None:
        obj = MISPObject('url')
        obj.add_attribute('url', type='url', value=artifact.address)
        obj.add_attribute('comment', type='comment', value=f"Artifact from case {case_number}, IOC level: {artifact.ioc_level}", distribution=0)
        self.finalize_misp_object(event_id, obj, case_number, artifact.ioc_level)
        self.check_and_update_monthly_misp(obj, case_number, artifact.ioc_level)

    def add_ip_artifact(self, event_id: str, artifact: IP, case_number: Any) -> None:
        obj = MISPObject('domain-ip')
        obj.add_attribute('ip', type='ip-src', value=artifact.address)
        obj.add_attribute('comment', type='comment', value=f"Artifact from case {case_number}, IOC level: {artifact.ioc_level}", distribution=0)
        self.finalize_misp_object(event_id, obj, case_number, artifact.ioc_level)
        self.check_and_update_monthly_misp(obj, case_number, artifact.ioc_level)

    def add_hash_artifact(self, event_id: str, artifact: Hash, case_number: Any) -> None:
        obj = MISPObject('file')
        hash_type_map = {'sha-256': 'sha256', 'sha-1': 'sha1', 'md2': 'md5'}
        hash_type = hash_type_map.get(artifact.type.lower(), artifact.type.lower())
        if hash_type not in ['md5', 'sha1', 'sha256']:
            logger.warning(f"Unsupported hash type '{hash_type}' for case {case_number}")
            return
        obj.add_attribute(hash_type, type=hash_type, value=artifact.value)
        obj.add_attribute('comment', type='comment', value=f"Artifact from case {case_number}, IOC level: {artifact.ioc_level}", distribution=0)
        self.finalize_misp_object(event_id, obj, case_number, artifact.ioc_level)
        self.check_and_update_monthly_misp(obj, case_number, artifact.ioc_level)

    def add_domain_artifact(self, event_id: str, artifact: Domain, case_number: Any) -> None:
        obj = MISPObject('domain-ip')
        obj.add_attribute('domain', type='domain', value=artifact.value)
        obj.add_attribute('comment', type='comment', value=f"Artifact from case {case_number}, IOC level: {artifact.ioc_level}", distribution=0)
        self.finalize_misp_object(event_id, obj, case_number, artifact.ioc_level)
        self.check_and_update_monthly_misp(obj, case_number, artifact.ioc_level)

    # ----------------------
    # Finalize object
    # ----------------------
    def finalize_misp_object(self, event_id: str, misp_object: MISPObject, case_number: Any, ioc_level: str) -> None:
        self.client.misp.add_object(event_id, misp_object)
