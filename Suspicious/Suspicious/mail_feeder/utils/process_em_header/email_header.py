import logging
from typing import List, Optional
from django.db import transaction
from mail_feeder.mail_utils.sim_hash.simhash import SimHashService
from mail_feeder.models import MailHeader

from .models import EmailHeaderData, SimilarityResult
from .utils import safe_execution


logger = logging.getLogger("tasp.cron.fetch_and_process_emails")

class EmailHeaderService:
    """
    Service layer for creating, validating, and updating MailHeader records.
    """

    def __init__(self, similarity_threshold: float = 1.0):
        self.text_distance = SimHashService()
        self.threshold = similarity_threshold

    def check_email_headers(self, email_data_header: str) -> List[MailHeader]:
        """
        Check and validate email headers against stored MailHeader instances.

        Args:
            email_data_header (str): The header text to compare.

        Returns:
            List[MailHeader]: Headers that match or are similar to the provided input.
        """
        with safe_execution("checking email headers"):
            results = []
            # TODO : Find a Way to optimize this processing for large datasets
            # Currently commented out for performance considerations
            # fuzzy_hash = self.text_distance.hash_text_mail(str(email_data_header))
            # logger.debug(f"Computed fuzzy hash: {fuzzy_hash}")

            # emails = MailHeader.objects.all().only("id", "fuzzy_hash", "header_value", "times_sent")
            # logger.debug(f"Fetched {emails.count()} stored mail headers")

            # for email_header in emails:
            #     sim = self._compare_headers(fuzzy_hash, email_header)
            #     if sim.is_similar:
            #         self._update_similarity(email_header, email_data_header, sim)
            #         results.append(email_header)
            #         # Perfect match — no need to continue
            #         if sim.distance == 0:
            #             break

            return results

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

    # -------------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------------
    def _compare_bodies(self, new_fuzzy_hash: str, existing_mail_header: MailHeader) -> SimilarityResult:
        """
        Compare new fuzzy hash with stored mail header.
        """
        stored_hash = existing_mail_header.fuzzy_hash
        distance = self.text_distance.get_distance(new_fuzzy_hash, stored_hash)
        is_similar = distance < self.threshold
        return SimilarityResult(
            fuzzy_hash=stored_hash,
            distance=distance,
            is_similar=is_similar,
            threshold=self.threshold,
        )

    def _update_similarity(self, email_header: MailHeader, new_text: str, result: SimilarityResult) -> None:
        """
        Updates the mail header based on similarity result.
        """
        with safe_execution("update_similarity"), transaction.atomic():
            email_header.other_values = self.text_distance.get_simhash_object(new_text)
            email_header.times_sent += 1
            email_header.save(update_fields=["times_sent", "other_values"])
            logger.debug(
                f"Updated MailHeader {email_header.id}: distance={result.distance}, times_sent={email_header.times_sent}"
            )
