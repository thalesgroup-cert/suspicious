"""Reporter notification connector — final-result email on case completion.

Replaces the inline MailNotificationService call that lived in
score_process/scoring/update_handler.save_case_results. Ships enabled:
reporter notification is expected product behavior. send_final's own
user_analysis_informed flag keeps duplicate deliveries idempotent."""
from __future__ import annotations

import logging
import smtplib

from case_handler.models import Case
from connectors.base import (
    Connector,
    ConnectorManifest,
    HealthStatus,
    EVENT_CASE_FINALISED,
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
        events=(EVENT_CASE_FINALISED,),
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
