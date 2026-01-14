import logging
from contextlib import contextmanager

logger = logging.getLogger(__name__)


@contextmanager
def safe_execution(context: str):
    """
    Context manager for standardized exception handling and logging.
    """
    try:
        yield
    except Exception as e:
        logger.error(f"[EmailBodyService] Error during {context}: {e}", exc_info=True)
        raise
