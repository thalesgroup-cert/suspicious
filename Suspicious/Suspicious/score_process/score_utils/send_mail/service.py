import json
import logging
from pathlib import Path

from profiles.models import UserProfile

from .modification_service import ModificationEmailService
from .acknowledge_service import AcknowledgementEmailService
from .final_service import FinalEmailService

from .models import RetryConfig, SuspiciousConfig
from .utils import build_user_infos, send_with_retry


logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")

CONFIG_PATH = "/app/settings.json"


class MailNotificationService:
    """
    Service responsible for user-facing email notifications.
    """

    def __init__(
        self,
        suspicious_cfg: SuspiciousConfig,
        retry_cfg: RetryConfig,
    ):
        self.suspicious_email = suspicious_cfg.email
        self.retry_cfg = retry_cfg

    # ---------- factory ----------

    @classmethod
    def from_settings(cls, path: str = CONFIG_PATH) -> "MailNotificationService":
        with open(path) as f:
            raw = json.load(f)

        suspicious_cfg = SuspiciousConfig(**raw.get("suspicious", {}))
        retry_cfg = RetryConfig()

        return cls(suspicious_cfg, retry_cfg)

    # ---------- internal ----------

    def _send(self, action) -> bool:
        return send_with_retry(
            action,
            self.retry_cfg.max_retries,
            self.retry_cfg.base_delay,
        )

    def _user_allows(self, user, field: str) -> bool:
        profile = UserProfile.objects.filter(user=user).first()
        if not profile:
            return True
        return getattr(profile, field, True)

    # ---------- public API ----------

    def send_review_email(self, case) -> None:
        user = case.reporter
        if not user:
            return

        user_infos = build_user_infos(user)
        subject = f"Your submission n°{case.id} has been reviewed as: {case.results}"

        def action():
            ModificationEmailService(
                subject=subject,
                sender=self.suspicious_email,
                recipient=user,
                recipient_name=user_infos,
                case=case,
            ).send()

        if not self._send(action):
            logger.error(
                "Error while sending review email for case ID %s.", case.id
            )

    def send_acknowledgement(self, mail) -> None:
        if not mail.is_received or mail.user_reception_informed:
            return

        user = mail.user
        if not user or user == self.suspicious_email:
            return

        if not self._user_allows(user, "wants_acknowledgement"):
            logger.info("User %s opted out of acknowledgement emails.", user)
            return

        user_infos = build_user_infos(user)

        def action():
            AcknowledgementEmailService().send(
                recipient=user,
                recipient_name=user_infos,
            )

        if self._send(action):
            mail.user_reception_informed = True
            mail.save()
        else:
            logger.error(
                "Failed to send acknowledgement email for mail ID %s.", mail.id
            )

    def send_final(self, mail, case) -> None:
        if not mail:
            return

        user = mail.user
        if not user or user == self.suspicious_email:
            return

        if not self._user_allows(user, "wants_results"):
            logger.info("User %s opted out of final emails.", user)
            return

        user_infos = build_user_infos(user)
        subject = (
            f"SUSPICIOUS EMAIL ANALYSIS - Your analysis [{case.id}] is completed"
        )

        def action():
            FinalEmailService(
                subject=subject,
                sender=self.suspicious_email,
                recipient=user,
                case=case,
                recipient_name=user_infos,
            ).send()

        if self._send(action):
            mail.user_analysis_informed = True
            mail.save()
        else:
            logger.error(
                "Failed to send final email for case ID %s.", case.id
            )
