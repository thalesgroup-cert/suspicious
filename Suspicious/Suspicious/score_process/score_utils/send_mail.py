import os
import time
import logging
from profiles.models import UserProfile
from score_process.score_utils.templates.modification import ModifEmail
from score_process.score_utils.templates.final import FinalEmail
from score_process.score_utils.templates.acknowlegment import AcknowledgementEmail
import json
from pathlib import Path

CONFIG_PATH = "/app/settings.json"
with open(CONFIG_PATH) as config_file:
    config = json.load(config_file)

suspicious_config = config.get("suspicious", {})
SUSPICIOUS_EMAIL = suspicious_config.get("email")
# Setup a module-specific logger
update_cases_logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")
update_cases_logger.setLevel(logging.INFO)

# Constants for retry logic
MAX_RETRIES = 3
BASE_DELAY = 1  # in seconds


def send_with_retry(send_callable, max_retries=MAX_RETRIES, base_delay=BASE_DELAY):
    """
    Helper function to attempt sending an email with retries using exponential backoff.

    Args:
        send_callable (callable): A callable that sends an email.
        max_retries (int): Maximum number of attempts.
        base_delay (int): Base delay (in seconds) before retrying.

    Returns:
        bool: True if send_callable() succeeds, False otherwise.
    """
    for attempt in range(1, max_retries + 1):
        try:
            send_callable()
            update_cases_logger.info("Email sent successfully on attempt %d.", attempt)
            return True
        except Exception as e:
            update_cases_logger.warning(
                "Attempt %d failed: %s", attempt, e, exc_info=True
            )
            if attempt < max_retries:
                wait_time = base_delay * (2 ** (attempt - 1))
                update_cases_logger.info("Retrying in %d seconds...", wait_time)
                time.sleep(wait_time)
    return False


def send_review_email(case):
    """
    Send review email to the reporter.

    This function sends a review email to the reporter of a case, notifying them about the review results.

    Args:
        case (Case): The case object representing the reported case.
    """
    user = case.reporter
    # Build user info if available
    user_infos = (
        f"{user.first_name} {user.last_name}"
        if user.first_name and user.last_name
        else ""
    )
    sender = SUSPICIOUS_EMAIL
    mail_header = f"Your submission n°{case.id} has been reviewed as: {case.results}"

    def send_action():
        ModifEmail(mail_header, sender, user, case, user_infos).send()

    if not send_with_retry(send_action):
        update_cases_logger.error(
            "Error while sending review email for case ID %s.", case.id
        )


def user_acknowledge(mail):
    """
    Send an acknowledgement email to the user if the mail is received
    and the user hasn't been informed yet.

    Args:
        mail: The mail object.
    """
    try:
        if mail.is_received and not mail.user_reception_informed:
            user = mail.user
            user_profile = UserProfile.objects.filter(user=user).first()
            # Build user info string if available
            user_infos = (
                f"{user.first_name} {user.last_name}"
                if user.first_name and user.last_name
                else ""
            )
            update_cases_logger.debug(
                "Sending acknowledgement email to user with user_infos: %s", user_infos
            )
            # Check user validity (ensuring user is not marked as "suspicious")
            if user is not None and user != SUSPICIOUS_EMAIL:
                if not user_profile.wants_acknowledgement:
                    update_cases_logger.info(
                        "User %s has opted out of acknowledgement emails.", user
                    )
                    return

                def send_action():
                    AcknowledgementEmail(
                        "SUSPICIOUS EMAIL ANALYSIS - Your submission has been recorded",
                        str(SUSPICIOUS_EMAIL),
                        user,
                        user_infos,
                    ).send()

                if send_with_retry(send_action):
                    mail.user_reception_informed = True
                    mail.save()
                else:
                    update_cases_logger.error(
                        "Failed to send acknowledgement email for mail ID %s.", mail.id
                    )
    except Exception as e:
        update_cases_logger.error(
            "Error sending acknowledgement email: %s", e, exc_info=True
        )


def user_final_mail(mail, case):
    """
    Send final email to the user notifying that analysis is complete.

    Args:
        mail: The mail object.
        case: The related case object.
    """
    try:
        if mail:
            user = mail.user
            user_profile = UserProfile.objects.filter(user=user).first()
            user_infos = (
                f"{user.first_name} {user.last_name}"
                if user.first_name and user.last_name
                else ""
            )
            subject = (
                f"SUSPICIOUS EMAIL ANALYSIS - Your analysis [{case.id}] is completed"
            )
            sender_email = SUSPICIOUS_EMAIL
            update_cases_logger.info(
                "Sending final email to user with user_infos: %s", user_infos
            )
            if user is not None and user != SUSPICIOUS_EMAIL:
                if not user_profile.wants_results:
                    update_cases_logger.info(
                        "User %s has opted out of final emails.", user
                    )
                    return

                def send_action():
                    FinalEmail(subject, sender_email, user, case, user_infos).send()

                if send_with_retry(send_action):
                    mail.user_analysis_informed = True
                    mail.save()
                else:
                    update_cases_logger.error(
                        "Failed to send final email for case ID %s.", case.id
                    )
    except Exception as e:
        update_cases_logger.error("Error sending final email: %s", e, exc_info=True)
