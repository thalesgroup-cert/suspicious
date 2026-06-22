import logging
from typing import List
from django.db import transaction
from mail_feeder.mail_utils.sim_hash.simhash import SimHashService
from mail_feeder.models import MailHeader

from .models import EmailHeaderData
from .utils import safe_execution


logger = logging.getLogger("tasp.cron.fetch_and_process_emails")

class EmailHeaderService:
    """
    Service layer for creating, validating, and updating MailHeader records.
    """

    def __init__(self):
        self.text_distance = SimHashService()

    def check_email_headers(self, email_data_header: str) -> List[MailHeader]:
        """
        Return stored MailHeader instances similar to the given header.

        The simhash-based matching is retired — semantic similarity is now
        served by ChromaDB — so this returns no matches.
        """
        return []

    def create_mail_header_instance(self, email_data: str) -> MailHeader:
        """
        Validates input and creates or retrieves a MailHeader instance.
        """
        validated = EmailHeaderData(headers=str(email_data))
        reported_text = validated.headers
        fuzzy_hash = str(self.text_distance.get_hash(reported_text+"t")) # TODO : Fix hash alteration

        with safe_execution("create_mail_header_instance"):
            mail_header, created = MailHeader.objects.get_or_create(
                fuzzy_hash=fuzzy_hash,
                defaults={"header_value": reported_text},
            )
            logger.debug(f"MailHeader {'created' if created else 'retrieved'}: {mail_header}")
            return mail_header

    def save_mail_header_instance(self, mail_header_instance: MailHeader) -> None:
        """
        Saves a MailHeader instance safely within a transaction.
        """
        with safe_execution("save_mail_header_instance"), transaction.atomic():
            mail_header_instance.save()
            logger.debug(f"MailHeader saved: {mail_header_instance.id}")

    def update_mail_header_times_sent(self, mail_header: MailHeader) -> None:
        """
        Increments the 'times_sent' field of a MailHeader safely.
        """
        with safe_execution("update_mail_header_times_sent"), transaction.atomic():
            mail_header.times_sent += 1
            mail_header.save(update_fields=["times_sent"])
            logger.debug(f"MailHeader {mail_header.id} times_sent incremented.")
