import time
import logging
from typing import Callable

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


def build_user_infos(user) -> str:
    """
    Build a displayable user name from a Django User instance.
    """
    if not user:
        return ""

    if user.first_name and user.last_name:
        return f"{user.first_name} {user.last_name}"

    username = str(user).split("@")[0]
    parts = username.split(".")
    if len(parts) >= 2:
        return f"{parts[0].capitalize()} {parts[1].capitalize()}"

    return username.capitalize()

def log_event(level, event: str, **fields):
    logger.log(
        level,
        event,
        extra={"event": event, **fields},
    )


def send_with_retry(
    send_callable: Callable[[], None],
    max_retries: int,
    base_delay: int,
) -> bool:
    """
    Retry helper with exponential backoff.
    """
    for attempt in range(1, max_retries + 1):
        try:
            send_callable()
            logger.info("Email sent successfully on attempt %d.", attempt)
            return True
        except Exception as exc:
            logger.warning(
                "Attempt %d failed: %s", attempt, exc, exc_info=True
            )
            if attempt < max_retries:
                delay = base_delay * (2 ** (attempt - 1))
                logger.info("Retrying in %d seconds...", delay)
                time.sleep(delay)

    return False
