import json
import logging
from pathlib import Path

from profiles.models import UserProfile

from .modification_service import ModificationEmailService
from .acknowledge_service import AcknowledgementEmailService
from .final_service import FinalEmailService

from .models import EmailSubjectsConfig, RetryConfig, SuspiciousConfig
from .utils import log_event, build_user_infos, send_with_retry


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
        subjects: EmailSubjectsConfig,
    ):
        self.suspicious_email = suspicious_cfg.email
        self.retry_cfg = retry_cfg
        self.subjects = subjects

    # ---------- factory ----------

    @classmethod
    def from_settings(cls, path: str = CONFIG_PATH) -> "MailNotificationService":
        with open(path) as f:
            raw = json.load(f)

        suspicious_cfg = SuspiciousConfig(**raw.get("suspicious", {}))
        retry_cfg = RetryConfig()
        subjects = EmailSubjectsConfig(**raw.get("email_subjects", {}))

        return cls(suspicious_cfg, retry_cfg, subjects)

    # ---------- helpers ----------

    def _send_with_retry(self, action, *, email_type: str, **context) -> bool:
        success = send_with_retry(
            action,
            self.retry_cfg.max_retries,
            self.retry_cfg.base_delay,
        )

        log_event(
            logging.INFO if success else logging.ERROR,
            "email_send",
            email_type=email_type,
            success=success,
            retries=self.retry_cfg.max_retries,
            **context,
        )

        return success

    def _get_recipient(self, user) -> str | None:
        if not user:
            return None
        if user.email == self.suspicious_email:
            return None
        return user.email

    def _user_allows(self, user, field: str) -> bool:
        profile = UserProfile.objects.filter(user=user).first()
        return getattr(profile, field, True) if profile else True

    def _can_notify(self, user, opt_field: str | None = None) -> bool:
        if not self._get_recipient(user):
            return False
        if opt_field and not self._user_allows(user, opt_field):
            log_event(
                logging.INFO,
                "email_opt_out",
                user_id=user.id,
                field=opt_field,
            )
            return False
        return True

    # ---------- public API ----------

    def send_review_email(self, case) -> None:
        user = case.reporter
        if not self._can_notify(user):
            return

        recipient = user.email
        subject = self.subjects.review.format(
            case_id=case.id,
            result=case.results,
        )
        user_infos = build_user_infos(user)

        def action():
            ModificationEmailService(
                subject=subject,
                sender=self.suspicious_email,
                recipient=recipient,
                recipient_name=user_infos,
                case=case,
            )._send_action(
                user=recipient,
                user_infos=user_infos,
                subject=subject,
            )

        self._send_with_retry(
            action,
            email_type="review",
            case_id=case.id,
            recipient=recipient,
        )

    def send_acknowledgement(self, mail) -> None:
        if not mail.is_received or mail.user_reception_informed:
            return

        user = mail.user
        if not self._can_notify(user, "wants_acknowledgement"):
            return

        recipient = user.email
        subject = self.subjects.acknowledgement
        user_infos = build_user_infos(user)

        def action():
            AcknowledgementEmailService()._send_action(
                user=recipient,
                user_infos=user_infos,
                subject=subject,
            )

        if self._send_with_retry(
            action,
            email_type="acknowledgement",
            mail_id=mail.id,
            recipient=recipient,
        ):
            mail.user_reception_informed = True
            mail.save(update_fields=["user_reception_informed"])

    def send_final(self, mail, case) -> None:
        if not mail:
            return

        user = mail.user
        if not self._can_notify(user, "wants_results"):
            return

        recipient = user.email
        subject = self.subjects.final.format(case_id=case.id)
        user_infos = build_user_infos(user)

        def action():
            FinalEmailService(
                case=case,
                sender=self.suspicious_email,
                recipient=recipient,
                recipient_name=user_infos,
            )._send_action(user=recipient, subject=subject)

        if self._send_with_retry(
            action,
            email_type="final",
            case_id=case.id,
            recipient=recipient,
        ):
            mail.user_analysis_informed = True
            mail.save(update_fields=["user_analysis_informed"])
