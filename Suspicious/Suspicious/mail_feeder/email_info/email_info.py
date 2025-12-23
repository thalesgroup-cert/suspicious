import logging
from email.utils import parseaddr
from typing import Optional

from mail_feeder.utils.user_creation.creation import UserCreationService
from mail_feeder.models import MailInfo
from score_process.score_utils.send_mail.service import MailNotificationService

from .utils import safe_execution
from .models import MailInstanceModel, MailInfoData

fetch_mail_logger = logging.getLogger("tasp.cron.fetch_and_process_emails")


class MailInfoService:
    """
    Service for creating and managing MailInfo records.
    """

    def __init__(self, user_creator: Optional[UserCreationService] = None):
        self.user_creator = user_creator or UserCreationService()

    def create_mail_info(self, mail_instance) -> MailInfo:
        """
        Create and persist MailInfo, return instance.
        """
        with safe_execution("creating MailInfo"):
            validated_mail = self._validate_mail_instance(mail_instance)
            user_email = self._extract_origin_email(validated_mail.reportedBy)
            mail_info_data = self._build_mail_info_data(validated_mail, user_email)

            mail_info_instance = self._save_mail_info(mail_info_data, mail_instance)
            self._acknowledge_user(mail_info_instance)
            return mail_info_instance

    def _validate_mail_instance(self, mail_instance) -> MailInstanceModel:
        """
        Validates that the mail_instance has correct fields using Pydantic.
        """
        return MailInstanceModel(
            reportedBy=mail_instance.reportedBy,
            times_sent=getattr(mail_instance, "times_sent", 1)
        )

    def _extract_origin_email(self, reported_by: str) -> str:
        """
        Extracts and normalizes the reporter's email address.
        """
        _, origin_mail = parseaddr(reported_by)
        fetch_mail_logger.info(f"Reported by: {origin_mail}")
        return origin_mail

    def _build_mail_info_data(self, mail: MailInstanceModel, user_email: str) -> MailInfoData:
        """
        Build validated MailInfo data object from mail instance.
        """
        is_phishing = mail.times_sent >= 15
        return MailInfoData(
            user_email=user_email,
            mail_id=str(id(mail)),
            is_received=True,
            is_phishing=is_phishing,
        )

    def _save_mail_info(self, data: MailInfoData, mail_instance):
        """
        Save MailInfo to the database.
        """
        user = self.user_creator.get_or_create_user(data.user_email)

        reception_ok = MailInfo(
            user=user,
            mail=mail_instance,
            is_received=data.is_received,
            is_phishing=data.is_phishing,
        )
        reception_ok.save()
        fetch_mail_logger.info(f"MailInfo created for {data.user_email}")
        return reception_ok

    def _acknowledge_user(self, mail_info_instance):
        """
        Trigger acknowledgment for the user.
        """
        try:
            cls = MailNotificationService.from_settings()
            cls.send_acknowledgement(mail_info_instance)
            fetch_mail_logger.info(f"Acknowledgment sent for user {mail_info_instance.user}")
        except Exception as e:
            fetch_mail_logger.error(f"Failed to send acknowledgment: {e}")
