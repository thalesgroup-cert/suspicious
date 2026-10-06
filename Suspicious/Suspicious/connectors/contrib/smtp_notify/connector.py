"""Reporter notification connector: acknowledgement when the case is created,
review email when an analyst changes the verdict, final result on completion.

Ships enabled: reporter notification is expected product behavior. The
user_reception_informed / user_analysis_informed flags keep duplicate
deliveries idempotent, and a failed send raises so the framework retries it."""
from __future__ import annotations

import logging
import smtplib

from case_handler.models import Case
from connectors.base import (
    Connector,
    ConnectorManifest,
    HealthStatus,
    EVENT_CASE_CREATED,
    EVENT_CASE_FINALISED,
    EVENT_CASE_MODIFIED,
)
from mail_feeder.models import MailInfo
from score_process.score_utils.send_mail.service import MailNotificationService

logger = logging.getLogger("connectors.contrib.smtp_notify")


class SmtpNotifyConnector(Connector):
    manifest = ConnectorManifest(
        name="smtp_notify",
        version="1.0.0",
        author="Thales CERT",
        category="Notifications",
        description="Email the reporter their case verdict. Uses the shared "
                    "email.smtp / email.content config sections.",
        config_schema=(),
        events=(EVENT_CASE_CREATED, EVENT_CASE_FINALISED, EVENT_CASE_MODIFIED),
        enabled_by_default=True,
    )

    def health_check(self) -> HealthStatus:
        from settings.config import get_section
        smtp = get_section("email.smtp")
        host, port = smtp.get("server"), int(smtp.get("port", 25) or 25)
        if not host:
            return HealthStatus(ok=False, detail="email.smtp.server not configured")
        try:
            with smtplib.SMTP(host, port, timeout=10) as server:
                server.ehlo()
            return HealthStatus(ok=True, detail=f"SMTP {host}:{port} reachable")
        except Exception as exc:  # noqa: BLE001 — health check must not raise
            return HealthStatus(ok=False, detail=str(exc))

    @staticmethod
    def _case_mail(case_id: int):
        case = Case.objects.select_related("fileOrMail").get(pk=case_id)
        return getattr(case.fileOrMail, "mail", None) if case.fileOrMail else None

    def on_case_created(self, event) -> None:
        mail = self._case_mail(event.case_id)
        if mail is None:
            return
        try:
            mail_info = MailInfo.objects.get(mail=mail)
        except MailInfo.DoesNotExist:
            # The case is created just before ingest records MailInfo: retry.
            raise RuntimeError(f"MailInfo not written yet for case {event.case_id}") from None
        MailNotificationService.from_settings().send_acknowledgement(mail_info)

    def on_case_modified(self, event) -> None:
        try:
            case = Case.objects.get(pk=event.case_id)
        except Case.DoesNotExist:
            return
        MailNotificationService.from_settings().send_review_email(case)

    def on_case_finalised(self, event) -> None:
        if event.status != "Done":
            return
        case = Case.objects.select_related("fileOrMail").get(pk=event.case_id)
        mail = getattr(case.fileOrMail, "mail", None) if case.fileOrMail else None
        if mail is None:
            return
        try:
            mail_info = MailInfo.objects.get(mail=mail)
        except MailInfo.DoesNotExist:
            logger.warning(
                "MailInfo missing for mail of case %s — skipping reporter email",
                event.case_id,
            )
            return
        MailNotificationService.from_settings().send_final(mail_info, case)
