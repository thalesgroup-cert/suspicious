import time
import logging
from pathlib import Path
from typing import Callable

from jinja2 import Environment, FileSystemLoader

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")

_TEMPLATES_DIR = Path(__file__).parent / "templates"


def load_email_template(template_name: str):
    """Load a Jinja2 email template from the send_mail templates dir with
    HTML autoescaping. Shared by every email service so the Environment is
    configured in one place."""
    env = Environment(
        loader=FileSystemLoader(_TEMPLATES_DIR),
        autoescape=True,
    )
    return env.get_template(template_name)


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


def load_email_config() -> dict:
    """Return the email section for templating + SMTP.

    Non-secret content (links/content/logos/socials/templates) comes from the
    runtime tier; the SMTP block is read via the ``email.smtp`` section so the
    SMTP password is overlaid from Vault. Shape matches the old
    ``settings.json["email"]`` dict so call sites are unchanged.
    """
    from settings.config import get_section
    cfg = dict(get_section("email"))
    cfg["smtp"] = get_section("email.smtp")
    return cfg
