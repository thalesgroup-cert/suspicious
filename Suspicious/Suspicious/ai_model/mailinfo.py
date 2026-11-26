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


def has_assessment(case) -> bool:
    """True when an earlier AI job of the case succeeded (its AiAssessment is stored)."""
    from ai_model.models import AiAssessment

    return AiAssessment.objects.filter(case=case).exclude(model_version="").exists()


def mark_ai_missing(case) -> None:
    """No AI result will come: what the Cortex path wrote when its AI job failed or never ran,
    so scoring treats the AI vote as missing (``ai_missing``) instead of the "Suspicious" default."""
    from case_handler.models import Result

    case.results_ai = Result.INCONCLUSIVE
    case.save(update_fields=["results_ai"])


def dispatch_mail_ai(case) -> list[str]:
    """Hand the case's mail to the engine offering the AI role; with no job started (no engine
    offers it, or every start was refused), mark the AI missing. Returns the ledger job ids."""
    from connectors import engines
    from connectors.base import DATA_TYPE_MAIL_ARCHIVE

    ids = engines.dispatch(value=case, data_type=DATA_TYPE_MAIL_ARCHIVE, case=case)
    if not ids:
        mark_ai_missing(case)
    return ids
