from pymisp import MISPObject
from ip_process.models import IP
from url_process.models import URL
from hash_process.models import Hash
from domain_process.models import Domain
from score_process.scoring.header_parser import parse_email_headers
import logging

logger = logging.getLogger(__name__)

def build_email_object(mail, case_number, detection_level) -> MISPObject:
    logger.debug(f"[MISPHandler] Adding email object for case {case_number}.")
    try:
        parsed_headers = parse_email_headers(mail.mail_header.header_value)
        cleaned_subject = mail.subject.replace("\n", " ").replace("\r", "")
        obj = MISPObject('email')
        obj.comment = f"Case: {case_number}, Detection level: {detection_level}"

        obj.add_attribute('from', value=parsed_headers.get('from', ''))
        obj.add_attribute('from-display-name', value=parsed_headers.get('from_display_name', ''))
        obj.add_attribute('to', value=parsed_headers.get('to', ''))
        obj.add_attribute('to-display-name', value=parsed_headers.get('to_display_name', ''))
        obj.add_attribute('cc', value=parsed_headers.get('cc', ''))
        obj.add_attribute('subject', value=cleaned_subject)
        obj.add_attribute('reply-to', value=parsed_headers.get('reply_to', ''))
        obj.add_attribute('return-path', value=parsed_headers.get('return_path', ''))
        obj.add_attribute('user-agent', value=parsed_headers.get('user_agent', ''))
        obj.add_attribute('send-date', value=parsed_headers.get('send_date', ''))

        return obj
    except Exception as e:
        logger.error(f"[MISPHandler] Error adding email object for case {case_number}: {e}", exc_info=True)
        return None

def build_url_object(url: URL, case_number: str, detection_level: str) -> MISPObject:
    obj = MISPObject('url')
    obj.add_attribute('url', type='url', value=url.address)
    obj.add_attribute('comment', type='comment', value=f"Artifact from case {case_number}, IOC level: {detection_level}", distribution=0)
    return obj

def build_ip_object(ip: IP, case_number: str, detection_level: str) -> MISPObject:
    obj = MISPObject('domain-ip')
    obj.add_attribute('ip', type='ip-src', value=ip.address)
    obj.add_attribute('comment', type='comment', value=f"Artifact from case {case_number}, IOC level: {detection_level}", distribution=0)
    return obj

def build_hash_object(hash_obj: Hash, case_number: str, detection_level: str) -> MISPObject:
    obj = MISPObject('file')
    hash_type_map = {'sha-256': 'sha256', 'sha-1': 'sha1', 'md2': 'md5'}
    hash_type = hash_type_map.get(hash_obj.type.lower(), hash_obj.type.lower())
    if hash_type not in ['md5', 'sha1', 'sha256']:
        logger.warning(f"Unsupported hash type '{hash_type}' for case {case_number}")
        return
    obj.add_attribute(hash_type, type=hash_type, value=hash_obj.value)
    obj.add_attribute('comment', type='comment', value=f"Artifact from case {case_number}, IOC level: {detection_level}", distribution=0)
    return obj

def build_domain_object(domain: Domain, case_number: str, detection_level: str) -> MISPObject:
    obj = MISPObject('domain-ip')
    obj.add_attribute('domain', type='domain', value=domain.value)
    obj.add_attribute('comment', type='comment', value=f"Artifact from case {case_number}, IOC level: {detection_level}", distribution=0)
    return obj


# ----------------------
# Finalize object
# ----------------------
def finalize_misp_object(misp, event_id: str, misp_object: MISPObject) -> None:
    misp.add_object(event_id, misp_object)