import logging

from .phishing import add_comment_to_item

logger = logging.getLogger(__name__)


def _thehive_config() -> dict:
    from settings.config import get_section
    return get_section("integrations.thehive")


def sync_case_comment_to_thehive(case, comment) -> None:
    if not _thehive_config().get("enabled", False):
        return
    if not case.thehive_alert_id:
        return

    message = f"**{comment.author.email}**"
    if comment.is_internal:
        message += " (internal)"
    message += f": {comment.body}"

    config = _thehive_config()
    add_comment_to_item(
        "alert", case.thehive_alert_id, {"message": message},
        config.get("url", ""), config.get("api_key", ""), always_append=True,
    )
