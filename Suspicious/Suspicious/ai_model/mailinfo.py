import logging

# Same logger as the cron path that used to own this logic (no behaviour change).
logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


def apply_mail_info(mail_info, category, result):
    """Update a MailInfo from the AI classification.

    Args:
        mail_info (MailInfo): The mail info object to update.
        category (str): The AI category (Case.category_ai).
        result (str): The AI result (Case.results_ai).
    """
    if not mail_info:
        logger.warning("No MailInfo provided to update")
        return

    try:
        mail_info.is_analyzed = True

        category_lower = (category or "").strip().lower()
        result_lower = (result or "").strip().lower()

        if category_lower in {"classic_phishing", "whaling", "clone"}:
            mail_info.is_phishing = True

        if result_lower == "dangerous":
            mail_info.is_dangerous = True

        mail_info.save()
        logger.info(
            f"MailInfo updated for Mail ID: {getattr(mail_info.mail, 'id', 'Unknown')}"
        )

    except Exception as e:
        logger.error(f"Error updating MailInfo: {e}")
