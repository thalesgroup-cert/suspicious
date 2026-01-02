import os
import logging
import uuid
from datetime import datetime
from email.header import decode_header, make_header

logger = logging.getLogger("tasp.cron.fetch_and_process_emails")

def decode_email_header(header_value: str) -> str:
    """
    Decode an encoded email header to a readable string.
    """
    try:
        return str(make_header(decode_header(header_value)))
    except Exception as e:
        logger.error(f"Failed to decode header '{header_value}': {e}")
        return header_value


def generate_unique_email_reference() -> str:
    """
    Generate a unique reference string for emails: YYMMDDHHMMSS-12hexchars
    """
    now = datetime.now()
    ref_date = now.strftime("%y%m%d%H%M%S")
    formatted_uuid = uuid.uuid4().hex[:12]
    return f"{ref_date}-{formatted_uuid}"


def ensure_dir(directory: str) -> None:
    """
    Ensure that a directory exists.
    """
    try:
        os.makedirs(directory, exist_ok=True)
    except Exception as e:
        logger.error(f"Failed to create directory '{directory}': {e}")
        raise
