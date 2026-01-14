import logging
from contextlib import contextmanager
from typing import List, Union, Optional

logger = logging.getLogger("tasp.cron.fetch_and_process_emails")

@contextmanager
def safe_execution(context: str):
    """
    Standardized try/except wrapper for logging and exception propagation.
    """
    try:
        yield
    except Exception as e:
        logger.error(f"[global_submissions] Error during {context}: {e}", exc_info=True)
        raise


def flatten_id_lists(*lists: List[Union[int, List[int]]]) -> List[int]:
    """
    Flattens multiple lists of IDs into a single list.
    """
    return [i for sublist in lists for i in (sublist if isinstance(sublist, list) else [sublist])]

def extract_email_address(from_header: str) -> Optional[str]:
    """
    Parses an email address from the 'From' header.

    Args:
        from_header: Raw string from the 'From' header.

    Returns:
        Parsed email address or None if invalid.
    """
    from email.utils import parseaddr
    _, email_addr = parseaddr(from_header)
    if not email_addr or "@" not in email_addr:
        return None
    return email_addr