"""
Email header parsing utilities.
"""
import ast
import logging
import re
from email.parser import Parser

update_cases_logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


def extract_email_address(header_value: str) -> str:
    match = re.search(r'<([^>]+)>', header_value)
    return match.group(1) if match else header_value


def extract_display_name(header_value: str):
    match = re.search(r'^(.*)<[^>]+>', header_value)
    return match.group(1).strip() if match else None


def parse_email_headers(header_value) -> dict:
    """
    Parse email headers from list-of-tuples, string, or dict into a flat
    lowercase-key dict with required fields extracted.
    """
    update_cases_logger.debug("Parsing email headers: %r", header_value)

    parsed_headers: dict = {}

    if isinstance(header_value, list):
        for key, value in header_value:
            key_lower = key.lower()
            if key_lower in parsed_headers:
                existing = parsed_headers[key_lower]
                parsed_headers[key_lower] = (
                    existing + [value] if isinstance(existing, list) else [existing, value]
                )
            else:
                parsed_headers[key_lower] = value

    elif isinstance(header_value, str):
        try:
            evaluated = ast.literal_eval(header_value)
            if isinstance(evaluated, dict):
                parsed_headers = {k.lower(): v for k, v in evaluated.items()}
                update_cases_logger.debug("Parsed headers from evaluated string: %r", parsed_headers)
            else:
                update_cases_logger.warning("Evaluated string is not a dict: %r", evaluated)
        except (SyntaxError, ValueError) as exc:
            update_cases_logger.warning(
                "Could not evaluate header string: %s — falling back to raw parser.", exc
            )
            raw = Parser().parsestr(header_value)
            parsed_headers = {k.lower(): v for k, v in raw.items()}
            update_cases_logger.debug("Parsed headers from raw string: %r", parsed_headers)

    elif isinstance(header_value, dict):
        parsed_headers = {k.lower(): v for k, v in header_value.items()}

    else:
        raise ValueError("Unsupported header format: %s" % type(header_value))

    result = {
        "from":              extract_email_address(parsed_headers.get("from", "")),
        "from_display_name": extract_display_name(parsed_headers.get("from", "")),
        "to":                extract_email_address(parsed_headers.get("to", "")),
        "to_display_name":   extract_display_name(parsed_headers.get("to", "")),
        "cc":                extract_email_address(parsed_headers.get("cc", "")),
        "subject":           parsed_headers.get("subject"),
        "reply_to":          extract_email_address(parsed_headers.get("reply-to", "")),
        "return_path":       parsed_headers.get("return-path"),
        "user_agent":        parsed_headers.get("user-agent"),
        "send_date":         parsed_headers.get("date"),
    }
    update_cases_logger.debug("Parsed result: %r", result)
    return result