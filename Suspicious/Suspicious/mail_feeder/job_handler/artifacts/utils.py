import logging
from contextlib import contextmanager

logger = logging.getLogger("artifacts")


@contextmanager
def safe_execution(context: str):
    """
    Wraps code in try/except for consistent logging.
    """
    try:
        yield
    except Exception as e:
        logger.error(f"[ArtifactService] Error during {context}: {e}", exc_info=True)
        raise
