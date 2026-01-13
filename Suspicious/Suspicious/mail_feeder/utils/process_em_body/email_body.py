import logging
from typing import List, Optional
from django.db import transaction
from mail_feeder.mail_utils.sim_hash.simhash import SimHashService
from mail_feeder.models import MailBody

from .models import EmailBodyData, SimilarityResult
from .utils import safe_execution


logger = logging.getLogger("tasp.cron.fetch_and_process_emails")


class EmailBodyService:
    """
    Service to process, compare, and manage email bodies.
    """

    def __init__(self, similarity_threshold: float = 1.0):
        self.text_distance = SimHashService()
        self.threshold = similarity_threshold

    def check_email_bodies(self, email_data_body: str) -> List[MailBody]:
        """
        Check and validate email bodies against stored MailBody instances.

        Args:
            email_data_body (str): The body text to compare.

        Returns:
            List[MailBody]: Bodies that match or are similar to the provided input.
        """
        with safe_execution("check_email_bodies"):
            results = []
            # TODO : Find a Way to optimize this processing for large datasets
            # Currently commented out for performance considerations
            # fuzzy_hash = self.text_distance.hash_text_mail(str(email_data_body))
            # logger.debug(f"Computed fuzzy hash: {fuzzy_hash}")

            # emails = MailBody.objects.all().only("id", "fuzzy_hash", "body_value", "times_sent")
            # logger.debug(f"Fetched {emails.count()} stored mail bodies")

            # for email_body in emails:
            #     sim = self._compare_bodies(fuzzy_hash, email_body)
            #     if sim.is_similar:
            #         self._update_similarity(email_body, email_data_body, sim)
            #         results.append(email_body)
            #         # Perfect match — no need to continue
            #         if sim.distance == 0:
            #             break

            return results

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

    # -------------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------------
    def _compare_bodies(self, new_fuzzy_hash: str, existing_mail_body: MailBody) -> SimilarityResult:
        """
        Compare new fuzzy hash with stored mail body.
        """
        stored_hash = existing_mail_body.fuzzy_hash
        distance = self.text_distance.get_distance(new_fuzzy_hash, stored_hash)
        is_similar = distance < self.threshold
        return SimilarityResult(
            fuzzy_hash=stored_hash,
            distance=distance,
            is_similar=is_similar,
            threshold=self.threshold,
        )

    def _update_similarity(self, email_body: MailBody, new_text: str, result: SimilarityResult) -> None:
        """
        Updates the mail body based on similarity result.
        """
        with safe_execution("update_similarity"), transaction.atomic():
            email_body.other_values = self.text_distance.get_simhash_object(new_text)
            email_body.times_sent += 1
            email_body.save(update_fields=["times_sent", "other_values"])
            logger.debug(
                f"Updated MailBody {email_body.id}: distance={result.distance}, times_sent={email_body.times_sent}"
            )
