import requests
import pybreaker
from common.http_client import make_session, get_breaker, RETRY
from datetime import datetime
from secrets import token_hex
import logging
from score_process.score_utils.thehive.utils import extract_urls, extract_mails, parse_headers
import os
from email.header import decode_header, make_header
import re


def _thehive_config() -> dict:
    from settings.config import get_section
    return get_section("integrations.thehive")


def _certificate_path():
    return _thehive_config().get("certificate_path") or True


proxies = {
    "http": None,
    "https": None,
}

PHISHING_CAMPAIGN_TEMPLATE = {
    "title": lambda subject: f"Potential phishing campaign: {subject}",
    "description": lambda classification, sub_classification, email_example: (
        f"A potential phishing campaign has been detected. "
        f"The AI Analyzer classified the emails as {sub_classification} ({classification}). "
        f"\n\n---\n\nExample email:\n```\n{email_example}\n```"
    ),
    "severity": 1,
    "tlp": 1,
    "pap": 1,
    "tags": ['enisa:nefarious-activity-abuse="phishing-attack"', "email", "campaign", "suspicious"],
}

NEW_MAIL_IN_CAMPAIGN_TEMPLATE = {
    "message": lambda timestamp, suspicious_case_id, n_mail: (
        f"New mail in phishing campaign detected at {timestamp} "
        f"in suspicious case {suspicious_case_id}. Total mails: {n_mail}"
    ),
}

logger = logging.getLogger(__name__)
update_cases_logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")

_session = make_session()
_thehive_breaker = get_breaker("thehive")


@RETRY
def _thehive_request(method: str, url: str, **kwargs) -> requests.Response:
    """Execute a TheHive HTTP request with timeout, retry, and circuit breaker.

    Calls response.raise_for_status() so callers get HTTPError on non-2xx.
    CircuitBreakerError is NOT retried by RETRY — it propagates immediately.
    """
    with _thehive_breaker.calling():
        response = _session.request(method, url, **kwargs)
        response.raise_for_status()
        return response


def generate_ref() -> str:
    return datetime.now().strftime("%y%m%d") + "-" + str(token_hex(3))[:5]


def create_new_alert(ticket_id, title, description, severity, tlp, pap, app_name, thehive_url, api_key, tags=None):
    if ticket_id is None:
        ticket_id = generate_ref()

    try:
        severity = int(severity)
    except (ValueError, TypeError):
        severity = 1

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
        "customFields": {"tha-id": ticket_id},
    }

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }

    url = f"{thehive_url}/api/v1/alert"
    try:
        response = _thehive_request("POST", url, headers=headers, json=alert_data, verify=_certificate_path())
        return response.json()
    except pybreaker.CircuitBreakerError as e:
        update_cases_logger.warning("[breaker:thehive] open — create_new_alert skipped: %s", e)
    except requests.exceptions.HTTPError as e:
        error_msg = f"HTTP Error creating alert: {e}"
        if e.response is not None and e.response.text:
            error_msg += f"\nResponse: {e.response.text}"
        update_cases_logger.error(error_msg)
    except ValueError as e:
        update_cases_logger.error(f"Error parsing response: {e}")
    except Exception as e:
        update_cases_logger.error(f"Error creating alert: {e}")

    return None


def build_mail_attachments_paths(headers, eml, txt, html, suspicious_case_id):
    attachments = []
    os.makedirs("/tmp/attachments", exist_ok=True)

    for ext, content in [("headers", headers), ("eml", eml), ("txt", txt), ("html", html)]:
        if content:
            path = f"/tmp/attachments/{suspicious_case_id}.{ext}"
            with open(path, "w") as f:
                f.write(content)
            attachments.append(path)

    return attachments


def build_mail_observables_from_html(html):
    return [
        {
            "dataType": "url",
            "data": url,
            "tlp": 1,
            "pap": 1,
            "tags": ["url", "suspicious", 'enisa:nefarious-activity-abuse="phishing-attack"'],
            "message": "Mail body URL",
        }
        for url in extract_urls(html)
    ]


def decode_mime_header(value):
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


def build_mail_observables_from_headers(str_headers):
    headers = parse_headers(str_headers)
    observables = []

    if headers.get("Subject"):
        decoded_subject = decode_mime_header(headers["Subject"][0])
        observables.append({
            "dataType": "mail-subject",
            "data": decoded_subject,
            "tlp": 1,
            "pap": 1,
            "tags": ["subject", "suspicious", 'enisa:nefarious-activity-abuse="phishing-attack"'],
            "message": "Mail subject",
        })

    for key, label, message in [
        ("From", "sender", "Mail sender"),
        ("Reply-To", "reply-to", "Reply-To"),
        ("In-Reply-To", "in-reply-to", "In-Reply-To"),
    ]:
        if not headers.get(key):
            continue
        value = headers[key][0] if key != "In-Reply-To" else headers[key]
        observables.append({
            "dataType": "other",
            "data": str(value),
            "tlp": 1,
            "pap": 1,
            "tags": [label, "suspicious", 'enisa:nefarious-activity-abuse="phishing-attack"'],
            "message": f'"{key}" header field',
        })
        mails = extract_mails(str(value))
        if mails:
            observables.append({
                "dataType": "mail",
                "data": mails[0],
                "tlp": 1,
                "pap": 1,
                "tags": [label, "suspicious", 'enisa:nefarious-activity-abuse="phishing-attack"'],
                "message": message,
            })

    return observables


def get_item_from_id(item_id, thehive_url, api_key):
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }

    for item_type in ["case", "alert"]:
        url = f"{thehive_url}/api/v1/{item_type}/{item_id}"
        try:
            response = _thehive_request("GET", url, headers=headers, verify=_certificate_path())
            return item_type, response.json()
        except pybreaker.CircuitBreakerError as e:
            update_cases_logger.warning("[breaker:thehive] open — get_item_from_id skipped: %s", e)
            return None, None
        except requests.exceptions.HTTPError:
            # Non-200 (e.g. 404 — item is not this type); try next type
            continue
        except requests.exceptions.RequestException as e:
            update_cases_logger.error(f"Error retrieving {item_type} with ID {item_id}: {e}")

    return None, None


def add_observables_to_item(item_type, item_id, observable_data, thehive_url, api_key):
    if item_type not in ("alert", "case"):
        update_cases_logger.error(f"add_observables_to_item: invalid item_type {item_type!r}, skipping")
        return

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    url = f"{thehive_url}/api/v1/{item_type}/{item_id}/observable"

    for observable in observable_data:
        try:
            _thehive_request("POST", url, headers=headers, json=observable, verify=_certificate_path())
        except pybreaker.CircuitBreakerError as e:
            update_cases_logger.warning("[breaker:thehive] open — add_observables_to_item skipped: %s", e)
            return
        except requests.exceptions.RequestException as e:
            update_cases_logger.error(f"Error adding observable {observable.get('data')}: {e}")


def add_attachments_to_item(item_type, item_id, attachment_paths, thehive_url, api_key):
    if item_type not in ("alert", "case"):
        update_cases_logger.error(f"add_attachments_to_item: invalid item_type {item_type!r}, skipping")
        return

    headers = {"Authorization": f"Bearer {api_key}"}
    url = f"{thehive_url}/api/v1/{item_type}/{item_id}/attachments"

    for file_path in attachment_paths:
        try:
            with open(file_path, "rb") as f:
                _thehive_request(
                    "POST", url,
                    headers=headers,
                    files=[("attachments", (os.path.basename(file_path), f))],
                    verify=_certificate_path(),
                )
        except pybreaker.CircuitBreakerError as e:
            update_cases_logger.warning("[breaker:thehive] open — add_attachments_to_item skipped: %s", e)
            return
        except requests.exceptions.RequestException as e:
            update_cases_logger.error(f"Error adding attachment {file_path}: {e}")
        except Exception as e:
            update_cases_logger.error(f"Error opening attachment {file_path}: {e}")


def add_comment_to_item(item_type, item_id, comment, thehive_url, api_key):
    if item_type not in ("alert", "case"):
        update_cases_logger.error(f"add_comment_to_item: invalid item_type {item_type!r}, skipping")
        return

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    url_add_comment = f"{thehive_url}/api/v1/{item_type}/{item_id}/comment"
    def url_modify_comment(comment_id):
        return f"{thehive_url}/api/v1/comment/{comment_id}/"
    url_query_comments = f"{thehive_url}/api/v1/query?name=get-alert-comments-{item_id}"
    query_comments = {
        "query": [
            {
                "_name": {"alert": "getAlert", "case": "getCase"}[item_type],
                "idOrName": item_id,
            },
            {"_name": "comments"},
            {"_name": "sort", "_fields": [{"_createdAt": "desc"}]},
            {"_name": "page", "from": 0, "to": 1},
        ]
    }

    try:
        response = _thehive_request(
            "POST", url_query_comments,
            json=query_comments, headers=headers, verify=_certificate_path(),
        )
        response_data = response.json()

        if response_data:
            existing = response_data[0]
            too_old = existing["createdAt"] < (datetime.now().timestamp() * 1000) - 600000
            wrong_user = existing["createdBy"] != _thehive_config().get("user")
            if too_old or wrong_user:
                _thehive_request("POST", url_add_comment, headers=headers, json=comment, verify=_certificate_path())
            else:
                _thehive_request(
                    "PATCH", url_modify_comment(existing["_id"]),
                    headers=headers, json=comment, verify=_certificate_path(),
                )
        else:
            _thehive_request("POST", url_add_comment, headers=headers, json=comment, verify=_certificate_path())

    except pybreaker.CircuitBreakerError as e:
        update_cases_logger.warning("[breaker:thehive] open — add_comment_to_item skipped: %s", e)
    except requests.exceptions.RequestException as e:
        update_cases_logger.error(f"Error querying comments for {item_type} {item_id}: {e}")
        # Fallback: attempt to post a new comment directly
        try:
            _thehive_request("POST", url_add_comment, headers=headers, json=comment, verify=_certificate_path())
        except pybreaker.CircuitBreakerError as e2:
            update_cases_logger.warning("[breaker:thehive] open — fallback comment skipped: %s", e2)
        except requests.exceptions.RequestException as e2:
            update_cases_logger.error(f"Error adding comment to {item_type} {item_id}: {e2}")