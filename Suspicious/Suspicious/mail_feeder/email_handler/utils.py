import logging
from contextlib import contextmanager
from typing import Generator

logger = logging.getLogger("tasp.cron.fetch_and_process_emails")
@contextmanager
def safe_operation(context: str) -> Generator[None, None, None]:
    """
    Context manager for safe operations with uniform error logging.
    """
    try:
        yield
    except Exception as e:
        logger.error(f"[email_handler] Error in {context}: {e}", exc_info=True)
        raise


def increment_field(instance, field_name: str) -> None:
    """
    Safely increments an integer field on a Django model-like instance.
    """
    value = getattr(instance, field_name, 0)
    setattr(instance, field_name, value + 1)
