import os
import logging
from contextlib import contextmanager

logger = logging.getLogger("tasp.cron.fetch_and_process_emails")

@contextmanager
def safe_execution(context: str):
    """
    Context manager for standardized exception logging.
    """
    try:
        yield
    except Exception as e:
        logger.error(f"[web_submission] Error during {context}: {e}", exc_info=True)
        raise
