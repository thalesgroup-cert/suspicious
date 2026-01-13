import logging
from contextlib import contextmanager

logger = logging.getLogger(__name__)


@contextmanager
def safe_execution(context: str):
    """
    Context manager that wraps code in a try/except block with standardized logging.
    """
    try:
        yield
    except Exception as e:
        logger.error(f"[AttachmentService] Error during {context}: {e}", exc_info=True)
