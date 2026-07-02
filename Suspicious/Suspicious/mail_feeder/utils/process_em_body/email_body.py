import logging
from typing import List
from django.db import transaction
from mail_feeder.mail_utils.sim_hash.simhash import SimHashService
from mail_feeder.models import MailBody

from .models import EmailBodyData
from .utils import safe_execution


logger = logging.getLogger("tasp.cron.fetch_and_process_emails")


class EmailBodyService:
    """
    Service to process, compare, and manage email bodies.
    """

    def __init__(self):
        self.text_distance = SimHashService()

    def check_email_bodies(self, email_data_body: str) -> List[MailBody]:
        """
        Return stored MailBody instances similar to the given body.

        The simhash-based matching is retired — semantic similarity is now
        served by ChromaDB — so this returns no matches.
        """
        return []

    def create_mail_body_instance(self, email_data: str) -> MailBody:
        """
        Validates input and creates or retrieves a MailBody instance.
        """
        validated = EmailBodyData(reportedText=str(email_data))
        reported_text = validated.reportedText
        fuzzy_hash = str(self.text_distance.get_hash(reported_text))
        with safe_execution("create_mail_body_instance"):
            mail_body, created = MailBody.objects.get_or_create(
                fuzzy_hash=fuzzy_hash,
                defaults={"body_value": reported_text},
            )
            logger.debug(f"MailBody {'created' if created else 'retrieved'}: {mail_body}")
            return mail_body

    def save_mail_body_instance(self, mail_body_instance: MailBody) -> None:
        """
        Saves a MailBody instance safely within a transaction.
        """
        with safe_execution("save_mail_body_instance"), transaction.atomic():
            mail_body_instance.save()
            logger.debug(f"MailBody saved: {mail_body_instance.id}")

    def update_mail_body_times_sent(self, mail_body: MailBody) -> None:
        """
        Increments the 'times_sent' field of a MailBody safely.
        """
        with safe_execution("update_mail_body_times_sent"), transaction.atomic():
            mail_body.times_sent += 1
            mail_body.save(update_fields=["times_sent"])
            logger.debug(f"MailBody {mail_body.id} times_sent incremented.")
