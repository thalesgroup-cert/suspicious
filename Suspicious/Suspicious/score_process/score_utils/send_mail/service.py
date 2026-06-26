import logging

from profiles.models import UserProfile

from .modification_service import ModificationEmailService
from .acknowledge_service import AcknowledgementEmailService
from .final_service import FinalEmailService

from .models import EmailSubjectsConfig, RetryConfig, SuspiciousConfig
from .utils import log_event, build_user_infos, send_with_retry


logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


class MailNotificationService:
    """
    Service responsible for user-facing email notifications.

    Each send method resolves the recipient's UserProfile so the
    individual email services can theme the message according to the
    user's chosen theme and semantic colors.
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

    # ── factory ────────────────────────────────────────────────────────────

    @classmethod
    def from_settings(cls, path: str = None) -> "MailNotificationService":
        from settings.config import get_section
        branding = get_section("branding")
        email_section = get_section("email")
        suspicious_cfg = SuspiciousConfig(email=branding.get("contact_email", ""))
        retry_cfg = RetryConfig()
        subjects = EmailSubjectsConfig(**email_section.get("templates", {}))
        return cls(suspicious_cfg, retry_cfg, subjects)

    # ── helpers ────────────────────────────────────────────────────────────

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

    def _reporter_address(self, mail, user) -> str | None:
        """Recipient for reporter notifications.

        Prefer the address captured at submission (``Mail.reportedBy``): the
        resolved ``user`` may be a fallback (e.g. an unknown external reporter
        mapped to the system user), which would otherwise suppress the email.
        Never notify the system mailbox itself.
        """
        related = getattr(mail, "mail", None)
        addr = (getattr(related, "reportedBy", "") or "").strip()
        if not addr:
            addr = (getattr(user, "email", "") or "").strip() if user else ""
        if not addr or addr == self.suspicious_email:
            return None
        return addr

    def _user_allows(self, user, field: str) -> bool:
        profile = UserProfile.objects.filter(user=user).first()
        return getattr(profile, field, True) if profile else True

    def _can_notify(self, user, opt_field: str | None = None) -> bool:
        if not self._get_recipient(user):
            return False
        if opt_field and not self._user_allows(user, opt_field):
            log_event(logging.INFO, "email_opt_out", user_id=user.id, field=opt_field)
            return False
        return True

    def _get_profile(self, user) -> "UserProfile | None":
        """
        Return the UserProfile for a user, or None if not found.
        The profile carries .theme and .semantic_colors which are
        forwarded to the email service so the message is rendered
        in the user's chosen visual style.
        """
        if not user:
            return None
        return UserProfile.objects.filter(user=user).first()

    # ── public API ─────────────────────────────────────────────────────────

    def send_review_email(self, case) -> None:
        user = case.reporter
        if not self._can_notify(user):
            return

        recipient = user.email
        subject = self.subjects.review.format(case_id=case.id, result=case.results)
        user_infos = build_user_infos(user)
        profile = self._get_profile(user)

        def action():
            ModificationEmailService(
                subject=subject,
                sender=self.suspicious_email,
                recipient=recipient,
                recipient_name=user_infos,
                case=case,
                profile=profile,        # ← theme context
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
        profile = self._get_profile(user)

        def action():
            AcknowledgementEmailService(
                profile=profile,        # ← theme context
            )._send_action(
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
        recipient = self._reporter_address(mail, user)
        if not recipient:
            return
        if user and not self._user_allows(user, "wants_results"):
            log_event(logging.INFO, "email_opt_out", user_id=user.id, field="wants_results")
            return

        subject = self.subjects.final.format(case_id=case.id)
        user_infos = build_user_infos(user)
        profile = self._get_profile(user)

        def action():
            FinalEmailService(
                case=case,
                sender=self.suspicious_email,
                recipient=recipient,
                recipient_name=user_infos,
                profile=profile,        # ← theme context
            )._send_action(user=recipient, subject=subject)

        if self._send_with_retry(
            action,
            email_type="final",
            case_id=case.id,
            recipient=recipient,
        ):
            mail.user_analysis_informed = True
            mail.save(update_fields=["user_analysis_informed"])