import logging
from contextlib import contextmanager
from typing import Optional

logger = logging.getLogger("tasp.cron.fetch_and_process_emails")

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



