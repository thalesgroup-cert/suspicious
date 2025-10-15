import requests
from datetime import datetime
from secrets import token_hex
import ast
import logging
from score_process.score_utils.utils import extract_urls, extract_mails, parse_headers
import os
import json
from email.header import decode_header, make_header  # Added for decoding MIME encoded headers
import re  # Added for detecting encoded-word patterns

CONFIG_PATH = "/app/settings.json"
with open(CONFIG_PATH) as config_file:
    config = json.load(config_file)

thehive_config = config.get('thehive', {})

certificate_path = thehive_config.get('certificate_path', '')

proxies = {
    "http": None,
    "https": None
}

PHISHING_CAMPAIGN_TEMPLATE = {
    "title": lambda subject: f"Potential phishing campaign: {subject}",
    "description": lambda classification, sub_classification, email_example: f"A potential phishing campaign has been detected. The AI Analyzer classified the emails as {sub_classification} ({classification}). \n\n---\n\nExample email:\n```\n{email_example}\n```",
    "severity": 1,
    "tlp": 1,
    "pap": 1,
    "tags": ["enisa:nefarious-activity-abuse=\"phishing-attack\"", "email", "campaign", "suspicious"]
}

NEW_MAIL_IN_CAMPAIGN_TEMPLATE = {
    "message": lambda timestamp, suspicious_case_id, n_mail: f"New mail in phishing campaign detected at {timestamp} in suspicious case {suspicious_case_id}. Total mails: {n_mail}",
}


logger = logging.getLogger(__name__)
update_cases_logger = logging.getLogger('tasp.cron.update_ongoing_case_jobs')

def generate_ref():
    """
    Generate unique 'sourceRef' for an alert.
    """
    ref = datetime.now().strftime("%y%m%d") + "-" + str(token_hex(3))[:5]
    return ref

def create_new_alert(ticket_id, title, description, severity, tlp, pap, app_name, thehive_url, api_key, tags=None):
    """
    Create a new alert in TheHive.
    
    Args:
        ticket_id (str): Unique identifier for the alert
        title (str): Alert title
        description (str): Alert description
        severity (int): Alert severity (1: low, 2: medium, 3: high, 4: critical)
        app_name (str): Name of the application creating the alert
        thehive_url (str): TheHive instance URL
        api_key (str): TheHive API key
        tags (list, optional): List of tags for the alert. Defaults to ["suspicious"]
        
    Returns:
        str: Alert ID if successful, error message if failed
    """
    if ticket_id is None:
        ticket_id = generate_ref()

    # Ensure severity is an integer
    try:
        severity = int(severity)
    except (ValueError, TypeError):
        severity = 1  # Default to low severity if conversion fails

    # Set default tags if none provided
    if tags is None:
        tags = ["suspicious"]

    alert_data = {
        "title": title,
        "description": description,
        "severity": severity,
        "tlp": tlp,
        "pap": pap,
        "type": app_name,
        "source": "suspicious",
        "sourceRef": ticket_id,
        "tags": tags,
        "customFields": {
            "tha-id": ticket_id
        }
    }

    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {api_key}'
    }

    url = f"{thehive_url}/api/v1/alert"
    try:
        response = requests.post(url, headers=headers, json=alert_data, verify=certificate_path)
        response.raise_for_status()
        alert = response.json()
        return alert
    except requests.exceptions.HTTPError as e:
        error_msg = f"HTTP Error creating alert: {e}"
        if response.text:
            error_msg += f"\nResponse: {response.text}"
        update_cases_logger.info(error_msg)
    except ValueError as e:
        error_msg = f"Error parsing response: {e}\nResponse content: {response.text}"
        update_cases_logger.info(error_msg)
    except Exception as e:
        error_msg = f"Error creating alert: {e}"
        update_cases_logger.info(error_msg)

    return None, None

def build_mail_attachments_paths(headers, eml, txt, html, suspicious_case_id):
    attachments = []

    os.makedirs(f"/tmp/attachments", exist_ok=True)

    if headers:
        with open(f"/tmp/attachments/{suspicious_case_id}.headers", "w") as f:
            f.write(headers)
        attachments.append(f"/tmp/attachments/{suspicious_case_id}.headers")
    if eml:
        with open(f"/tmp/attachments/{suspicious_case_id}.eml", "w") as f:
            f.write(eml)
        attachments.append(f"/tmp/attachments/{suspicious_case_id}.eml")
    if txt:
        with open(f"/tmp/attachments/{suspicious_case_id}.txt", "w") as f:
            f.write(txt)
        attachments.append(f"/tmp/attachments/{suspicious_case_id}.txt")
    if html:
        with open(f"/tmp/attachments/{suspicious_case_id}.html", "w") as f:
            f.write(html)
        attachments.append(f"/tmp/attachments/{suspicious_case_id}.html")

    return attachments

def build_mail_observables_from_html(html):
    observables = []
    # Extract URLs from the HTML content
    urls = extract_urls(html)
    for url in urls:
        observables.append({
            "dataType": "url",
            "data": url,
            "tlp": 1,
            "pap": 1,
            "tags": ["url", "suspicious", "enisa:nefarious-activity-abuse=\"phishing-attack\""],
            "message": "Mail body URL"
        })
    return observables

def decode_mime_header(value):
    """Decode a MIME encoded (RFC 2047) header value if needed.
    Falls back gracefully if decoding fails.
    Args:
    value (str \| list): Raw header value (possibly list from parser)
    Returns:
    str: Decoded unicode string
    """
    try:
        if isinstance(value, list):
            value = value[0]
        if not isinstance(value, str):
            value = str(value)
        # Detect RFC 2047 encoded-word pattern: =?charset?B/Q?....?=
        if re.search(r"=\?.+?\?[bBqQ]\?.+?\?=", value):
            # Use email.header utilities to decode properly
            return str(make_header(decode_header(value)))
        return value
    except Exception:
        return str(value)

def build_mail_observables_from_headers(str_headers):
    headers = parse_headers(str_headers)

    observables = []

    if "Subject" in headers and headers["Subject"]:
        raw_subject = headers["Subject"][0]
        decoded_subject = decode_mime_header(raw_subject)
        observables.append({
            "dataType": "mail-subject",
            "data": decoded_subject,
            "tlp":1,
            "pap":1,
            "tags":["subject","suspicious","enisa:nefarious-activity-abuse=\"phishing-attack\""],
            "message":"Mail subject"
        })
    if "From" in headers and headers["From"]:
        observables.append({
            "dataType": "other",
            "data": str(headers["From"][0]),
            "tlp":1,
            "pap":1,
            "tags": ["sender", "suspicious", "enisa:nefarious-activity-abuse=\"phishing-attack\""],
            "message": "\"From\" header field"
        })
        observables.append({
            "dataType": "mail",
            "data": extract_mails(headers["From"][0])[0],
            "tlp":1,
            "pap":1,
            "tags": ["sender", "suspicious", "enisa:nefarious-activity-abuse=\"phishing-attack\""],
            "message": "Mail sender"
        })
    if "Reply-To" in headers and headers["Reply-To"]:
        observables.append({
            "dataType": "other",
            "data": str(headers["Reply-To"][0]),
            "tlp":1,
            "pap":1,
            "tags": ["reply-to", "suspicious", "enisa:nefarious-activity-abuse=\"phishing-attack\""],
            "message": "\"Reply-To\" header field"
        })
        observables.append({
            "dataType": "mail",
            "data": extract_mails(headers["Reply-To"][0])[0],
            "tlp":1,
            "pap":1,
            "tags": ["reply-to", "suspicious", "enisa:nefarious-activity-abuse=\"phishing-attack\""],
            "message": "Reply-To"
        })
    if "In-Reply-To" in headers and headers["In-Reply-To"]:
        observables.append({
            "dataType": "other",
            "data": str(headers["In-Reply-To"]),
            "tlp":1,
            "pap":1,
            "tags": ["in-reply-to", "suspicious", "enisa:nefarious-activity-abuse=\"phishing-attack\""],
            "message": "\"In-Reply-To\" header field"
        })
        observables.append({
            "dataType": "mail",
            "data": extract_mails(headers["In-Reply-To"])[0],
            "tlp":1,
            "pap":1,
            "tags": ["in-reply-to", "suspicious", "enisa:nefarious-activity-abuse=\"phishing-attack\""],
            "message": "In-Reply-To"
        })

    return observables

def get_item_from_id(item_id, thehive_url, api_key):
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {api_key}'
    }

    for item_type in ['case', 'alert']:
        url = f"{thehive_url}/api/v1/{item_type}/{item_id}"
        try:
            response = requests.get(url, headers=headers, verify=certificate_path)
            if response.status_code == 200:
                return item_type, response.json()
        except requests.exceptions.RequestException as e:
            update_cases_logger.error(f"Error retrieving {item_type} with ID {item_id}: {e}")
    
    return None, None

def add_observables_to_item(item_type, item_id, observable_data, thehive_url, api_key):
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {api_key}'
    }
    url = f"{thehive_url}/api/v1/{item_type.lower()}/{item_id}/observable"

    for observable in observable_data:
        try:
            response = requests.post(url, headers=headers, json=observable, verify=certificate_path)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            error_msg = f"Error while adding observable {observable['data']}: {e}"
            update_cases_logger.info(error_msg)

def add_attachments_to_item(item_type, item_id, attachment_paths, thehive_url, api_key):
    headers = {
        'Authorization': f'Bearer {api_key}'
    }
    url = f"{thehive_url}/api/v1/{item_type.lower()}/{item_id}/attachments"

    for file_path in attachment_paths:
        try:
            with open(file_path, "rb") as f:
                files = [
                    ("attachments", (file_path.split("/")[-1], f))
                ]

                response = requests.post(url, headers=headers, files=files, verify=certificate_path)
                response.raise_for_status()

        except requests.exceptions.RequestException as e:
            error_msg = f"Error while adding attachment {file_path}: {e}"
            update_cases_logger.info(error_msg)
        except Exception as e:
            error_msg = f"Error opening or sending attachment {file_path}: {e}"
            update_cases_logger.info(error_msg)

def add_comment_to_item(item_type, item_id, comment, thehive_url, api_key):
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {api_key}'
    }
    url_add_comment = f"{thehive_url}/api/v1/{item_type.lower()}/{item_id}/comment"
    url_modify_comment = lambda comment_id: f"{thehive_url}/api/v1/comment/{comment_id}/"
    url_query_comments = f"{thehive_url}/api/v1/query?name=get-alert-comments-{item_id}"
    query_comments = {
        "query":[{
            "_name":{"alert": "getAlert", "case": "getCase"}[item_type.lower()],
            "idOrName": item_id
        },{
            "_name":"comments"
        },{
            "_name":"sort",
            "_fields":[{"_createdAt":"desc"}]
        },{
            "_name":"page",
            "from":0,
            "to":1
        }]
    }

    # Query existing comments
    try:
        response = requests.post(url_query_comments, json=query_comments, headers=headers, verify=certificate_path)
        response.raise_for_status()
        response_data = response.json()
        
        # Check if there are any comments
        if response_data and len(response_data) > 0:
            existing_comment = response_data[0]
            # if comment is older than 10 minutes or created by different user, add new comment, else modify it
            if existing_comment["createdAt"] < (datetime.now().timestamp() * 1000) - 600000 or existing_comment["createdBy"] != thehive_config.get('user'):
                response = requests.post(url_add_comment, headers=headers, json=comment, verify=certificate_path)
                response.raise_for_status()
            else:
                comment_id = existing_comment["_id"]
                response = requests.patch(url_modify_comment(comment_id), headers=headers, json=comment, verify=certificate_path)
                response.raise_for_status()
        else:
            # No existing comments, add a new one
            response = requests.post(url_add_comment, headers=headers, json=comment, verify=certificate_path)
            response.raise_for_status()
    except requests.exceptions.RequestException as e:
        error_msg = f"Error querying comments for {item_type} {item_id}: {e}"
        update_cases_logger.info(error_msg)
        # If query fails, try to add a new comment anyway
        try:
            response = requests.post(url_add_comment, headers=headers, json=comment, verify=certificate_path)
            response.raise_for_status()
        except requests.exceptions.RequestException as e2:
            error_msg2 = f"Error adding comment to {item_type} {item_id}: {e2}"
            update_cases_logger.info(error_msg2)