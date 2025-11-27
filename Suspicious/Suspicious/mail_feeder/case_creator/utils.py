import logging
from contextlib import contextmanager

logger = logging.getLogger("email_info")


@contextmanager
def safe_execution(context: str):
    """
    Context manager for standardized exception logging.
    """
    try:
        yield
    except Exception as e:
        logger.error(f"[email_info] Error during {context}: {e}", exc_info=True)
        raise
