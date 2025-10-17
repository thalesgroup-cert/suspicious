import logging
from contextlib import contextmanager
from typing import Optional

logger = logging.getLogger("minio_submissions")


@contextmanager
def safe_execution(context: str):
    """
    Context manager for standardized exception handling with logging.
    """
    try:
        yield
    except Exception as e:
        logger.error(f"[minio_submissions] Error during {context}: {e}", exc_info=True)
        raise


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
    return email_addr if email_addr else None
