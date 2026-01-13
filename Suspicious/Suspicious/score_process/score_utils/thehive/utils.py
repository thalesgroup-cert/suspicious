import os
import re
from datetime import datetime
from secrets import token_hex
from typing import List
from email.header import decode_header, make_header

from .models import Observable
from collections import Counter, defaultdict
import json
import ast
import logging
import html

logger = logging.getLogger(__name__)
update_cases_logger = logging.getLogger('tasp.cron.update_ongoing_case_jobs')

ATTACHMENTS_DIR = "/tmp/attachments"

def safe(value, default=None):
    return value if value not in (None, "") else default


def generate_ref() -> str:
    return datetime.now().strftime("%y%m%d") + "-" + token_hex(3)[:5]


def decode_mime_header(value) -> str:
    try:
        if isinstance(value, list):
            value = value[0]
        if not isinstance(value, str):
            value = str(value)
        if re.search(r"=\?.+?\?[bBqQ]\?.+?\?=", value):
            return str(make_header(decode_header(value)))
        return value
    except Exception:
        return str(value)


def build_mail_attachments(
    headers: str | None,
    eml: str | None,
    txt: str | None,
    html: str | None,
    case_id: str,
) -> List[str]:
    os.makedirs(ATTACHMENTS_DIR, exist_ok=True)
    attachments = []

    def _write(ext: str, content: str):
        path = f"{ATTACHMENTS_DIR}/{case_id}.{ext}"
        with open(path, "w") as f:
            f.write(content)
        attachments.append(path)

    if headers:
        _write("headers", headers)
    if eml:
        _write("eml", eml)
    if txt:
        _write("txt", txt)
    if html:
        _write("html", html)

    return attachments


def observables_from_html(html: str) -> List[Observable]:
    return [
        Observable(
            dataType="url",
            data=url,
            tags=["url", "suspicious", 'enisa:nefarious-activity-abuse="phishing-attack"'],
            message="Mail body URL",
        )
        for url in extract_urls(html)
    ]


def observables_from_headers(raw_headers: str) -> List[Observable]:
    headers = parse_headers(raw_headers)
    obs: List[Observable] = []

    if subject := headers.get("Subject"):
        decoded = decode_mime_header(subject[0])
        obs.append(
            Observable(
                dataType="mail-subject",
                data=decoded,
                tags=["subject", "suspicious", 'enisa:nefarious-activity-abuse="phishing-attack"'],
                message="Mail subject",
            )
        )

    def _mail_observable(value, label):
        return Observable(
            dataType="mail",
            data=extract_mails(value)[0],
            tags=[label, "suspicious", 'enisa:nefarious-activity-abuse="phishing-attack"'],
            message=label,
        )

    for key, label in [("From", "sender"), ("Reply-To", "reply-to"), ("In-Reply-To", "in-reply-to")]:
        if headers.get(key):
            value = str(headers[key][0])
            obs.append(
                Observable(
                    dataType="other",
                    data=value,
                    tags=[label, "suspicious", 'enisa:nefarious-activity-abuse="phishing-attack"'],
                    message=f'"{key}" header field',
                )
            )
            obs.append(_mail_observable(value, label))

    return obs

def build_mail_attachments_paths(eml: str, ticket_id: str) -> str:
    if not eml:
        return ""

    os.makedirs("/tmp/attachments", exist_ok=True)
    path = f"/tmp/attachments/{ticket_id}.eml"

    with open(path, "w") as f:
        f.write(eml)

    return path


def map_result_color(result: str) -> str:
    return {
        "Dangerous": "#EF3340",
        "Suspicious": "#FFAA4D",
        "Safe": "#00AB84",
        "Inconclusive": "#0085CA",
    }.get(result, "#000")

def extract_mails(string):
    pattern = r'[\w\.-]+@[\w\.-]+'
    return re.findall(pattern, string)

def extract_urls(text):
    """Extract URLs from plain text, Markdown, or HTML.

    Supports:
    - Plain URLs: https://example.com/path?x=1
    - Angle bracket URLs: <https://example.com>
    - Markdown links: [text](https://example.com)
    - HTML attributes: href="https://example.com", src='https://...'

    Returns a list of unique URLs (order preserved).
    """
    if not text:
        return []

    candidates = []

    # HTML href/src attributes (double or single quotes)
    attr_pattern = re.compile(r"\b(?:href|src)\s*=\s*(['\"])\s*(https?://[^'\"\s>]+)\1", re.IGNORECASE)
    for _quote, url in attr_pattern.findall(text):
        candidates.append(url)

    # Markdown links [text](url)
    md_link_pattern = re.compile(r"\[[^\]]+\]\(\s*(https?://[^) \t]+)\s*\)")
    candidates.extend(md_link_pattern.findall(text))

    # Angle bracket autolinks <url>
    angle_pattern = re.compile(r"<(https?://[^>\s]+)>")
    candidates.extend(angle_pattern.findall(text))

    # Plain URLs (avoid trailing punctuation / closing delimiters)
    plain_pattern = re.compile(r"(https?://[^\s<>'\"]+)")
    candidates.extend(plain_pattern.findall(text))

    # Normalise, strip trailing punctuation, HTML-unescape, de-duplicate, keep order
    urls = []
    seen = set()
    for raw in candidates:
        cleaned = html.unescape(raw).rstrip(').,;:!?\'\"]')
        if cleaned.startswith('http') and cleaned not in seen:
            seen.add(cleaned)
            urls.append(cleaned)
    return urls

def decode_mime_header(value):
    decoded_parts = decode_header(value)
    return ''.join(
        part.decode(charset or 'utf-8') if isinstance(part, bytes) else part
        for part, charset in decoded_parts
    )

def parse_headers(headers_str: str):
    headers = defaultdict(list)
    current_key = None
    current_value_lines = []

    for line in headers_str.splitlines():
        if not line.strip():
            continue  # skip empty lines

        if ":" in line and not line.startswith(" "):  
            # flush previous header
            if current_key is not None:
                headers[current_key].append(" ".join(current_value_lines).strip())
            
            # start new header
            key, value = line.split(":", 1)
            current_key = key.strip()
            current_value_lines = [value.strip()]
        else:
            # continuation of previous header (folded header)
            if current_key:
                current_value_lines.append(line.strip())

    # flush the last header
    if current_key is not None:
        headers[current_key].append(" ".join(current_value_lines).strip())

    return headers

def parse_and_decode_defaultdict(s):
    # Extract dict portion
    dict_str = s[s.find("{"):s.rfind("}")+1]

    # Convert string to dict
    raw_dict = ast.literal_eval(dict_str)

    # Decode MIME headers in list values
    decoded_dict = {}
    for key, values in raw_dict.items():
        decoded_list = []
        for val in values:
            if isinstance(val, str) and '=?' in val:
                try:
                    decoded_val = decode_mime_header(val)
                except Exception:
                    decoded_val = val  # Fallback
            else:
                decoded_val = val
            decoded_list.append(decoded_val)
        decoded_dict[key] = decoded_list

    return decoded_dict

def get_phishing_campaign(similar_mails):
    similar_threshold = 0.25
    campaign_threshold = 3

    phshing_campaign_mails = {
        'ids': [[]],
        'embeddings': [[]],
        'metadatas': [[]],
        'documents': [[]],
        'distances': [[]]
    }
    for i in range(len(similar_mails['ids'][0])):
        if similar_mails['distances'][0][i] < similar_threshold:
            update_cases_logger.info(f"-> Similar mail found ({similar_mails['distances'][0][i]} < {similar_threshold})")
            phshing_campaign_mails['ids'][0].append(similar_mails['ids'][0][i])
            phshing_campaign_mails['embeddings'][0].append(similar_mails['embeddings'][0][i])
            phshing_campaign_mails['metadatas'][0].append(similar_mails['metadatas'][0][i])
            phshing_campaign_mails['documents'][0].append(similar_mails['documents'][0][i])
            phshing_campaign_mails['distances'][0].append(similar_mails['distances'][0][i])

    if len(phshing_campaign_mails['ids'][0]) >= campaign_threshold:
        return phshing_campaign_mails
    else:
        return None
    
def get_most_common_alert_id(phishing_campaign):
    ids = []
    for mail in phishing_campaign['metadatas'][0]:
        if mail['alert_ids']:
            try:
                alert_ids = json.loads(mail['alert_ids'])
            except json.JSONDecodeError:
                try:
                    alert_ids = mail['alert_ids'].strip("'[]").split("', '")
                    alert_ids = [id.strip("'") for id in alert_ids]
                except Exception:
                    continue
            
            if alert_ids and alert_ids[0]:
                ids.extend(alert_ids)

    if ids:
        return Counter(ids).most_common()[0][0]
    else:
        return ''
    
def get_most_common_subject(phishing_campaign):
    subjects = []
    for mail in phishing_campaign['metadatas'][0]:
        if mail['headers']:
            str_headers = mail['headers']
            dict_part = str_headers[str_headers.find("{"):str_headers.rfind("}")+1]
            headers = ast.literal_eval(dict_part)
            subjects.append(headers.get('Subject', '')[0])
    if subjects:
        if Counter(subjects).most_common()[0][0]:
            return Counter(subjects).most_common()[0][0]
    return 'Unknown Subject'


def extract_sender_domain_from_headers(mail_headers):
    """
    Extract the sender domain from mail headers.
    Looks for 'From' field and extracts domain from email address.
    Returns None if domain cannot be extracted.
    """
    try:
        update_cases_logger.debug(f"Extracting sender domain from headers: {type(mail_headers)}")
        
        if isinstance(mail_headers, dict):
            # Look for 'From' field in headers (case insensitive)
            from_field = None
            for key in ['From', 'from', 'FROM']:
                if key in mail_headers:
                    from_field = mail_headers[key]
                    break
            
            update_cases_logger.debug(f"From field found: {from_field} (type: {type(from_field)})")
            
            if from_field:
                # Handle case where from_field is a list (take first element)
                if isinstance(from_field, list) and len(from_field) > 0:
                    from_field = from_field[0]
                
                # Ensure from_field is a string
                if not isinstance(from_field, str):
                    from_field = str(from_field)
                
                # Skip if it's None or empty string after conversion
                if not from_field or from_field.lower() in ['none', '']:
                    update_cases_logger.debug("From field is None or empty after conversion")
                    return None
                
                update_cases_logger.debug(f"Processing from_field as string: {from_field}")
                
                # Extract email address from "Name <email@domain.com>" format
                email_match = re.search(r'<([^>]+)>', from_field)
                if email_match:
                    email = email_match.group(1)
                else:
                    # If no angle brackets, assume the whole field is the email
                    email = from_field.strip()
                
                update_cases_logger.debug(f"Extracted email: {email}")
                
                # Extract domain from email
                if '@' in email:
                    domain = email.split('@')[1].strip()
                    domain = domain.lower()
                    update_cases_logger.debug(f"Extracted domain: {domain}")
                    return domain
        
        update_cases_logger.debug("No domain could be extracted")
        return None
    except Exception as e:
        update_cases_logger.error(f"Error extracting sender domain from headers: {e}")
        return None

def is_domain_in_campaign_allow_list(domain):
    """
    Check if a domain is in the campaign domains whitelist.
    Returns True if domain is whitelisted, False otherwise.
    """
    try:
        if not domain:
            update_cases_logger.debug("No domain provided for whitelist check")
            return False
        
        # Import here to avoid circular imports
        from settings.models import CampaignDomainAllowList

        # Check if domain exists in CampaignDomainAllowList
        # The domain field is a ForeignKey to Domain model, so we need to query by domain__value
        is_whitelisted = CampaignDomainAllowList.objects.filter(domain__value__exact=domain).exists()
        update_cases_logger.info(f"Domain '{domain}' allow list check: {is_whitelisted}")
        return is_whitelisted
    except Exception as e:
        update_cases_logger.error(f"Error checking campaign domain allow list: {e}")
        return False