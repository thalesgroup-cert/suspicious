"""Reporter notifications must reach the real reporter even when the reported_by
address doesn't resolve to a known user.

An external/unknown reporter gets mapped to a fallback (often the system user)
during user resolution. send_final previously sent to that resolved user's email,
so when the fallback equalled the system mailbox the email was silently dropped.
The real reporter address is preserved on Mail.reportedBy and must be preferred.
"""
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase

from score_process.score_utils.send_mail.models import (
    EmailSubjectsConfig, RetryConfig, SuspiciousConfig,
)
from score_process.score_utils.send_mail.service import MailNotificationService

SYS = "cert@meridian.example"


class ReporterRecipientTests(TestCase):
    def _svc(self):
        return MailNotificationService(
            SuspiciousConfig(email=SYS),
            RetryConfig(max_retries=1, base_delay=0),
            EmailSubjectsConfig(
                acknowledgement="ack", review="review", final="Analysis [{case_id}] done",
            ),
        )

    def _mail_info(self, resolved_email, reported_by):
        User = get_user_model()
        user = User.objects.create(username="sysuser", email=resolved_email)
        mi = MagicMock()
        mi.user = user
        mi.mail = MagicMock(reportedBy=reported_by)
        mi.user_analysis_informed = False
        return mi

    @patch("score_process.score_utils.send_mail.service.FinalEmailService")
    def test_final_goes_to_reportedby_when_user_is_system_fallback(self, FinalSvc):
        # reporter resolved to the system user, but the real reporter is alice
        mi = self._mail_info(resolved_email=SYS, reported_by="alice@meridian.example")
        case = MagicMock(id=7, results="Safe")
        self._svc().send_final(mi, case)
        # email was sent (not skipped) to the real reporter address
        self.assertTrue(FinalSvc.called, "send_final must not skip a real reporter")
        kwargs = FinalSvc.call_args.kwargs
        self.assertEqual(kwargs.get("recipient"), "alice@meridian.example")

    @patch("score_process.score_utils.send_mail.service.FinalEmailService")
    def test_final_skipped_when_reporter_is_the_system_mailbox(self, FinalSvc):
        # genuinely self-reported (reportedBy == system) → don't email ourselves
        mi = self._mail_info(resolved_email=SYS, reported_by=SYS)
        self._svc().send_final(mi, MagicMock(id=8, results="Safe"))
        self.assertFalse(FinalSvc.called)
