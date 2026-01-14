import logging
import email.header
from datetime import datetime as dt
from contextlib import contextmanager

logger = logging.getLogger("tasp.cron.fetch_and_process_emails")

@contextmanager
def safe_execution(context: str):
    """
    Context manager for consistent error logging.
    """
    try:
        yield
    except Exception as e:
        logger.error(f"[define_email] Error during {context}: {e}", exc_info=True)
        raise


def decode_subject(subject: str) -> str:
    """
    Decode MIME or encoded email subject lines safely.
    """
    decoded_subject = ""
    for part, encoding in email.header.decode_header(subject or ""):
        if isinstance(part, bytes):
            decoded_subject += part.decode(encoding or "utf-8", errors="replace")
        else:
            decoded_subject += part
    return decoded_subject or "No Subject"


def parse_email_date(date_string: str | None) -> dt:
    """
    Convert a string email date into a Python datetime (UTC naive).
    """
    if not date_string:
        return dt.now()
    try:
        return dt.strptime(date_string, "%a, %d %b %Y %H:%M:%S %z").replace(tzinfo=None)
    except ValueError:
        logger.warning(f"Invalid date format '{date_string}', using current timestamp.")
        return dt.now()
