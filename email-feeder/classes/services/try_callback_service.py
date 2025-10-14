import logging
import time
import typing

DEFAULT_MAX_RETRIES = 3
DEFAULT_BASE_DELAY = 1  # in seconds


def try_callback(
    logger: logging.Logger,
    callback: typing.Callable[[], None],
    max_retries: int = DEFAULT_MAX_RETRIES,
    base_delay: int = DEFAULT_BASE_DELAY,
) -> bool:
    """
    Attempt to execute a callback function with retries using exponential backoff.

    Args:
        callback (callable): A callable.
        max_retries (int): Maximum number of attempts.
        base_delay (int): Base delay (in seconds) before retrying.

    Returns:
        bool: True if callback() succeeds, False otherwise.
    """
    for attempt in range(1, max_retries + 1):
        try:
            callback()
            logger.info("Email sent successfully on attempt %d.", attempt)
            return True
        except Exception as e:
            logger.warning("Attempt %d failed: %s", attempt, e, exc_info=True)
            if attempt < max_retries:
                wait_time = base_delay * (2 ** (attempt - 1))
                logger.info("Retrying in %d seconds...", wait_time)
                time.sleep(wait_time)
    return False
