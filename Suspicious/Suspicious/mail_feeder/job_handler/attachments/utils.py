import logging
from contextlib import contextmanager

logger = logging.getLogger("tasp.cron.fetch_and_process_emails")

@contextmanager
def safe_execution(context: str):
    """
    Context manager for standardized exception handling and logging.
    """
    try:
        yield
    except Exception as e:
        logger.error(f"[AttachmentService] Error during {context}: {e}", exc_info=True)
        raise
