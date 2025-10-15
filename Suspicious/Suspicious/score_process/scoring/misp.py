from pymisp import ExpandedPyMISP, MISPEvent, MISPObject
import os
import logging
from datetime import datetime
from score_process.scoring.header_parser import parse_email_headers
from ip_process.models import IP
from url_process.models import URL
from hash_process.models import Hash
from typing import Optional, Any
import json
from pathlib import Path

CONFIG_PATH = "/app/settings.json"
with open(CONFIG_PATH) as config_file:
    config = json.load(config_file)

misp_config = config.get('misp', {})

logger = logging.getLogger(__name__)
update_cases_logger = logging.getLogger('tasp.cron.update_ongoing_case_jobs')


class MISPHandler:
    def __init__(self, primary: bool = True) -> None:
        """
        Initialize MISPHandler for two different MISP instances.

        Args:
            primary (bool): If True, connect to the primary MISP (email database).
                            If False, connect to the secondary MISP (malicious artifacts).
        """
        if primary:
            self.misp_url = misp_config['suspicious'].get("url", 'http://localhost:8880')
            self.misp_key = misp_config['suspicious'].get("key", 'default-primary-key')
        else:
            self.misp_url = misp_config['security'].get("url", 'https://secondary-misp.example.com')
            self.misp_key = misp_config['security'].get("key", 'default-secondary-key')
        self.misp = self.get_misp_instance()

    def get_misp_instance(self) -> ExpandedPyMISP:
        """
        Create and return a PyMISP instance using the configured URL and API key.
        """
        try:
            misp = ExpandedPyMISP(self.misp_url, self.misp_key, ssl=False)
            update_cases_logger.info("[MISPHandler] MISP instance created successfully.")
            return misp
        except Exception as e:
            update_cases_logger.error(f"[MISPHandler] Failed to create MISP instance: {e}", exc_info=True)
            raise

    def _find_event_by_name(self, event_name: str) -> Optional[str]:
        """
        Helper function to search for an event by name and return its event ID if found.

        Args:
            event_name (str): Name of the event to search for.

        Returns:
            Optional[str]: The event ID if found, otherwise None.
        """
        try:
            events = self.misp.search_index(eventinfo=event_name)
            update_cases_logger.debug(f"[MISPHandler] Search result for event '{event_name}': {events}")
            if events:
                if isinstance(events, dict) and 'response' in events and events['response']:
                    return events['response'][0].get('id')
                elif isinstance(events, list) and events:
                    return events[0].get('id')
            return None
        except Exception as e:
            update_cases_logger.error(f"[MISPHandler] Error searching for event '{event_name}': {e}", exc_info=True)
            return None

    def get_or_create_event_for_email(self, case: Any) -> Optional[MISPEvent]:
        """
        Create or retrieve a MISP event for a specific email case.

        Args:
            case: An object representing the email case. Must have attributes 'id' and 'results'.

        Returns:
            Optional[MISPEvent]: A MISPEvent object if successful, otherwise None.
        """
        event_name = f"Email Analysis - Case {case.id}"
        update_cases_logger.debug(f"[MISPHandler] Processing event for {event_name}.")

        try:
            event_id = self._find_event_by_name(event_name)
            if event_id:
                update_cases_logger.info(f"[MISPHandler] Found existing event {event_id} for {event_name}.")
                event = self.misp.get_event(event_id)
                self.add_case_number_attribute(event['Event'], case.id)
                detection_tag = self.get_detection_level_tag(case.results)
                event_obj = MISPEvent()
                event_obj.load(event['Event'])
                if detection_tag:
                    event_obj.add_tag(detection_tag)
                self.misp.update_event(event_obj)
                return event_obj

            update_cases_logger.debug(f"[MISPHandler] No existing event found for {event_name}. Creating new event.")
            # Create a new event
            event = MISPEvent()
            event.info = event_name
            event.date = datetime.now().strftime("%Y-%m-%d")
            event.distribution = 0
            event.threat_level_id = 3
            event.analysis = 1

            created_event = self.misp.add_event(event)
            if 'Event' in created_event and 'id' in created_event['Event']:
                event_id = created_event['Event']['id']
                update_cases_logger.info(f"[MISPHandler] Created new event {event_id} for {event_name}.")
                self.add_case_number_attribute(created_event['Event'], case.id)
                detection_tag = self.get_detection_level_tag(case.results)
                update_cases_logger.debug(f"[MISPHandler] Detection tag: {detection_tag}")
                event_obj = MISPEvent()
                event_obj.load(created_event['Event'])
                if detection_tag:
                    event_obj.add_tag(detection_tag)
                self.misp.update_event(event_obj)
                return event_obj
            else:
                update_cases_logger.error(f"[MISPHandler] Failed to retrieve event ID after creation for {event_name}.")
                return None
        except Exception as e:
            update_cases_logger.error(f"[MISPHandler] Error processing event for {event_name}: {e}", exc_info=True)
            return None

    def get_or_create_monthly_event(self) -> Optional[Any]:
        event_date = datetime.now().strftime("%Y-%m-01")
        event_name = f"MalSpam cases - {datetime.now().strftime('%B %Y')}"
        tags_config = misp_config.get('tags', {})

        try:
            event_id = self._find_event_by_name(event_name)
            if event_id:
                update_cases_logger.info(f"[MISPHandler] Found existing event {event_id} for {event_name}.")
                event = self.misp.get_event(event_id, pythonify=True)  # obtenir objet MISPEvent
                if event:
                    tags = self.parse_tags(tags_config)
                    for tag in tags:
                        event.add_tag(tag["name"])
                    return self.misp.update_event(event, pythonify=True)
                return None

            # Création du nouvel événement
            event = MISPEvent()
            event.info = event_name
            event.date = event_date
            event.distribution = 3
            event.threat_level_id = 3
            event.analysis = 1

            # Ajout des tags avant la création
            tags = self.parse_tags(tags_config)
            for tag in tags:
                event.add_tag(tag["name"])
            created = self.misp.add_event(event, pythonify=True)
            return created

        except Exception as e:
            update_cases_logger.error(f"[MISPHandler] Error creating or retrieving event: {e}")
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



    def update_misp(self, case: Any) -> None:
        """
        Create/update a MISP event for a specific email case by adding email details, attachments, and artifacts.

        Args:
            case: An object representing the email case.
        """
        try:
            case_number = case.id
            detection_level = case.results
            update_cases_logger.debug(f"[MISPHandler] Starting to update MISP for case {case_number}.")

            event = self.get_or_create_event_for_email(case)
            if not event or not hasattr(event, 'id'):
                update_cases_logger.error(f"[MISPHandler] Could not create or retrieve event for case {case_number}.")
                return

            event_id = event.id
            update_cases_logger.debug(f"[MISPHandler] Retrieved event {event_id} for case {case_number}.")

            if case.fileOrMail and hasattr(case.fileOrMail, 'mail'):
                mail = case.fileOrMail.mail
                self.add_email_object(event_id, mail, case_number, detection_level)

                if hasattr(mail, 'mail_attachments'):
                    for attachment in mail.mail_attachments.all():
                        self.add_attachment_object(event_id, attachment, case_number, detection_level)

                if hasattr(mail, 'mail_artifacts'):
                    for artifact in mail.mail_artifacts.all():
                        self.add_artifact_object(event_id, artifact, case_number, detection_level)

            if hasattr(case, 'nonFileIocs') and case.nonFileIocs:
                ioc_data = case.nonFileIocs.get_iocs()
                for ioc_type, ioc in ioc_data.items():
                    if ioc:
                        update_cases_logger.debug(f"[MISPHandler] Adding non-file artifact for case {case_number}, IOC type: {ioc_type}")
                        self.add_artifact_object(event_id, ioc, case_number, detection_level, ioc_type=ioc_type)
            else:
                update_cases_logger.info(f"[MISPHandler] No email or non-file IOCs to add for case {case_number}.")

            update_cases_logger.info(f"[MISPHandler] Successfully updated MISP with case {case_number}.")

        except Exception as e:
            update_cases_logger.error(f"[MISPHandler] Error updating MISP for case {case_number}: {e}", exc_info=True)

    def check_and_update_monthly_misp(self, misp_object: MISPObject, case_number: Any, ioc_level: str) -> None:
        """
        If the IOC level is malicious or suspicious, add the object to the monthly event on the secondary MISP.

        Args:
            misp_object (MISPObject): The object to add.
            case_number: The case number.
            ioc_level (str): The IOC level.
        """
        if ioc_level.upper() in ['MALICIOUS', 'SUSPICIOUS']:
            try:
                misp_handler_secondary = MISPHandler(primary=False)
                secondary_event = misp_handler_secondary.get_or_create_monthly_event()
                update_cases_logger.debug(f"[MISPHandler] Adding object to monthly event for case {case_number} in secondary MISP.")

                new_misp_object = MISPObject(misp_object.name)
                for attr in misp_object.attributes:
                    if attr.object_relation and attr.value:
                        attr_type = attr.type if getattr(attr, 'type', None) else attr.object_relation
                        new_misp_object.add_attribute(attr.object_relation, type=attr_type, value=attr.value)
                    else:
                        update_cases_logger.warning(f"[MISPHandler] Missing attribute type or value for case {case_number}, skipping attribute.")

                misp_handler_secondary.finalize_misp_object(secondary_event['Event']['id'], new_misp_object, case_number, ioc_level)
            except Exception as e:
                update_cases_logger.error(f"[MISPHandler] Error updating monthly event in secondary MISP for case {case_number}: {e}", exc_info=True)

    def add_email_object(self, event_id: str, mail: Any, case_number: Any, detection_level: str) -> None:
        """
        Add an email object to a MISP event.

        Args:
            event_id (str): ID of the MISP event.
            mail: Email object containing header and content details.
            case_number: The case number.
            detection_level (str): Detection level for tagging.
        """
        update_cases_logger.debug(f"[MISPHandler] Adding email object for case {case_number}.")
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
            update_cases_logger.info(f"[MISPHandler] Added email object to event {event_id} for case {case_number}. Response: {response}")
        except Exception as e:
            update_cases_logger.error(f"[MISPHandler] Error adding email object for case {case_number}: {e}", exc_info=True)

    def add_case_number_attribute(self, event: dict, case_number: Any) -> None:
        """
        Add the case number as an attribute to a MISP event.

        Args:
            event (dict): The MISP event data.
            case_number: The case number.
        """
        case_number_attribute = {
            'type': 'text',
            'value': str(case_number),
            'category': 'Other',
            'comment': 'Case Number'
        }
        response = self.misp.add_attribute(event['id'], case_number_attribute)
        update_cases_logger.info(f"[MISPHandler] Added case number attribute '{case_number}' to event {event['id']}. Response: {response}")

    def get_detection_level_tag(self, detection_level: str) -> str:
        """
        Map a detection level to its corresponding MISP tag.

        Args:
            detection_level (str): The detection level (e.g., 'Safe', 'Suspicious').

        Returns:
            str: The corresponding tag, or an empty string if not mapped.
        """
        detection_tags = {
            'Safe': 'level::SAFE',
            'Inconclusive': 'level::INCONCLUSIVE',
            'Suspicious': 'level::SUSPICIOUS',
            'Dangerous': 'level::DANGEROUS'
        }
        return detection_tags.get(detection_level.capitalize(), '')

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
                    update_cases_logger.warning(f"[MISPHandler] Unsupported or missing artifact type '{ioc_type}' for case {case_number}. Skipping.")
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
                    update_cases_logger.warning(f"[MISPHandler] Unsupported or missing artifact type '{artifact_type}' for case {case_number}. Skipping.")
        except Exception as e:
            update_cases_logger.error(f"[MISPHandler] Error adding artifact to event {event_id}: {e}", exc_info=True)

    def add_url_artifact(self, event_id: str, url_artifact: Any, case_number: Any) -> None:
        """
        Add a URL artifact to a MISP event.

        Args:
            event_id (str): ID of the MISP event.
            url_artifact: The URL artifact (object or string).
            case_number: The case number.
        """
        try:
            misp_object = MISPObject('url')
            url_address = url_artifact.address if hasattr(url_artifact, 'address') else url_artifact
            ioc_level = url_artifact.ioc_level if hasattr(url_artifact, 'ioc_level') else 'UNKNOWN'
            update_cases_logger.debug(f"[MISPHandler] Adding URL artifact for case {case_number}: {url_address}")
            misp_object.add_attribute('url', type='url', value=url_address)
            misp_object.add_attribute('comment', type='comment', value=f"Artifact from case {case_number}, IOC level: {ioc_level}", distribution=0)
            self.finalize_misp_object(event_id, misp_object, case_number, ioc_level)
            self.check_and_update_monthly_misp(misp_object, case_number, ioc_level)
        except Exception as e:
            update_cases_logger.error(f"[MISPHandler] Error adding URL artifact for case {case_number}: {e}", exc_info=True)

    def add_ip_artifact(self, event_id: str, ip_artifact: Any, case_number: Any) -> None:
        """
        Add an IP artifact to a MISP event.

        Args:
            event_id (str): ID of the MISP event.
            ip_artifact: The IP artifact (object or string).
            case_number: The case number.
        """
        try:
            misp_object = MISPObject('domain-ip')
            ip_address = ip_artifact.address if hasattr(ip_artifact, 'address') else ip_artifact
            ioc_level = ip_artifact.ioc_level if hasattr(ip_artifact, 'ioc_level') else 'UNKNOWN'
            update_cases_logger.debug(f"[MISPHandler] Adding IP artifact for case {case_number}: {ip_address}")
            misp_object.add_attribute('ip', type='ip-src', value=ip_address)
            misp_object.add_attribute('comment', type='comment', value=f"Artifact from case {case_number}, IOC level: {ioc_level}", distribution=0)
            self.finalize_misp_object(event_id, misp_object, case_number, ioc_level)
            self.check_and_update_monthly_misp(misp_object, case_number, ioc_level)
        except Exception as e:
            update_cases_logger.error(f"[MISPHandler] Error adding IP artifact for case {case_number}: {e}", exc_info=True)

    def add_hash_artifact(self, event_id: str, hash_artifact: Any, case_number: Any) -> None:
        """
        Add a hash artifact to a MISP event.

        Args:
            event_id (str): ID of the MISP event.
            hash_artifact: The hash artifact (object or string).
            case_number: The case number.
        """
        try:
            misp_object = MISPObject('file')
            hash_value = hash_artifact.value if hasattr(hash_artifact, 'value') else hash_artifact
            hash_type = hash_artifact.hashtype.lower() if hasattr(hash_artifact, 'hashtype') else 'unknown'
            ioc_level = hash_artifact.ioc_level if hasattr(hash_artifact, 'ioc_level') else 'UNKNOWN'
            if hash_type == 'sha-256' or hash_type == "snefru-256":
                hash_type = 'sha256'
            if hash_type == 'md2':
                hash_type = 'md5'
            if hash_type == 'sha-1':
                hash_type = 'sha1'
            if hash_type in ['md5', 'sha1', 'sha256']:
                update_cases_logger.debug(f"[MISPHandler] Adding hash artifact for case {case_number}: {hash_value} of type {hash_type}")
                misp_object.add_attribute(hash_type, type=hash_type, value=hash_value)
                misp_object.add_attribute('comment', type='comment', value=f"Artifact from case {case_number}, IOC level: {ioc_level}", distribution=0)
                self.finalize_misp_object(event_id, misp_object, case_number, ioc_level)
                self.check_and_update_monthly_misp(misp_object, case_number, ioc_level)
            else:
                update_cases_logger.warning(f"[MISPHandler] Unsupported hash type '{hash_type}' for case {case_number}. Skipping.")
        except Exception as e:
            update_cases_logger.error(f"[MISPHandler] Error adding hash artifact for case {case_number}: {e}", exc_info=True)

    def add_domain_artifact(self, event_id: str, domain_artifact: Any, case_number: Any) -> None:
        """
        Add a domain artifact to a MISP event.

        Args:
            event_id (str): ID of the MISP event.
            domain_artifact: The domain artifact (object or string).
            case_number: The case number.
        """
        try:
            misp_object = MISPObject('domain-ip')
            domain_name = domain_artifact.value if hasattr(domain_artifact, 'value') else domain_artifact
            ioc_level = domain_artifact.category if hasattr(domain_artifact, 'category') else 'UNKNOWN'
            update_cases_logger.debug(f"[MISPHandler] Adding domain artifact for case {case_number}: {domain_name}")
            misp_object.add_attribute('domain', type='domain', value=domain_name)
            misp_object.add_attribute('comment', type='comment', value=f"Artifact from case {case_number}, IOC level: {ioc_level}", distribution=0)
            self.finalize_misp_object(event_id, misp_object, case_number, ioc_level)
            self.check_and_update_monthly_misp(misp_object, case_number, ioc_level)
        except Exception as e:
            update_cases_logger.error(f"[MISPHandler] Error adding domain artifact for case {case_number}: {e}", exc_info=True)

    def finalize_misp_object(self, event_id: str, misp_object: MISPObject, case_number: Any, ioc_level: str) -> None:
        """
        Finalize a MISP object by sending it to MISP.

        Args:
            event_id (str): ID of the MISP event.
            misp_object (MISPObject): The object to add.
            case_number: The case number.
            ioc_level (str): The IOC level.
        """
        try:
            response = self.misp.add_object(event_id, misp_object)
            update_cases_logger.info(f"[MISPHandler] Added artifact to event {event_id} for case {case_number}. IOC level: {ioc_level}. Response: {response}")
        except Exception as e:
            update_cases_logger.error(f"[MISPHandler] Error finalizing MISP object for case {case_number}: {e}", exc_info=True)

    def add_attachment_object(self, event_id: str, attachment: Any, case_number: Any, detection_level: str) -> None:
        """
        Add an attachment object to a MISP event.

        Args:
            event_id (str): ID of the MISP event.
            attachment: The attachment object.
            case_number: The case number.
            detection_level (str): The detection level.
        """
        try:
            if attachment.file and hasattr(attachment.file, 'file_path'):
                misp_object = MISPObject('file')
                ioc_level = attachment.file.file_level if hasattr(attachment.file, 'file_level') else 'UNKNOWN'
                if ioc_level.upper() == 'SAFE-ALLOW_LISTED':
                    update_cases_logger.info(f"[MISPHandler] Skipping attachment for case {case_number} due to SAFE-ALLOW_LISTED IOC level.")
                    return

                file_path = attachment.file.file_path.name
                file_size = attachment.file.size
                update_cases_logger.debug(f"[MISPHandler] Adding attachment object for case {case_number}: {file_path}")
                misp_object.add_attribute('filename', value=file_path)
                misp_object.add_attribute('size-in-bytes', value=file_size)

                if attachment.file.linked_hash and attachment.file.linked_hash.value:
                    hash_value = attachment.file.linked_hash.value
                    hash_type = attachment.file.linked_hash.hashtype.lower()
                    if hash_type == 'sha-256':
                        hash_type = 'sha256'
                    if hash_type in ['md5', 'sha1', 'sha256']:
                        update_cases_logger.debug(f"[MISPHandler] Adding linked hash for case {case_number}: {hash_value} of type {hash_type}")
                        misp_object.add_attribute(hash_type, type=hash_type, value=hash_value)
                    else:
                        update_cases_logger.warning(f"[MISPHandler] Unsupported linked hash type '{hash_type}' for case {case_number}. Skipping linked hash.")

                self.finalize_misp_object(event_id, misp_object, case_number, ioc_level)
            else:
                update_cases_logger.warning(f"[MISPHandler] Attachment has no file for case {case_number}.")
        except Exception as e:
            update_cases_logger.error(f"[MISPHandler] Error adding attachment to event {event_id} for case {case_number}: {e}", exc_info=True)
