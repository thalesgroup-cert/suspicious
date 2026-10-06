"""Sending is one attempt that raises on failure: retrying (with the ledger and
the circuit breaker) is the connector framework's job, not an in-process
sleep loop inside the ingest or delivery worker."""
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase

from score_process.score_utils.send_mail.models import EmailSubjectsConfig, SuspiciousConfig
from score_process.score_utils.send_mail.service import MailNotificationService

SYS = "cert@meridian.example"
BASE = "score_process.score_utils.send_mail.service"


class SingleAttemptTests(TestCase):
    def setUp(self):
        self.svc = MailNotificationService(
            SuspiciousConfig(email=SYS),
            EmailSubjectsConfig(acknowledgement="ack", review="review {case_id} {result}", final="done {case_id}"),
        )
        self.user = get_user_model().objects.create(username="alice", email="alice@meridian.example")

    def _mail(self):
        mi = MagicMock()
        mi.user = self.user
        mi.is_received = True
        mi.user_reception_informed = False
        mi.user_analysis_informed = False
        mi.mail = MagicMock(reportedBy="alice@meridian.example")
        return mi

    def test_acknowledgement_failure_propagates_and_is_not_marked_sent(self):
        mi = self._mail()
        with patch(f"{BASE}.AcknowledgementEmailService") as svc, patch("time.sleep") as sleep:
            svc.return_value._send_action.side_effect = OSError("relay down")
            with self.assertRaises(OSError):
                self.svc.send_acknowledgement(mi)
        self.assertEqual(svc.return_value._send_action.call_count, 1)
        sleep.assert_not_called()
        self.assertFalse(mi.user_reception_informed)

    def test_acknowledgement_success_marks_sent(self):
        mi = self._mail()
        with patch(f"{BASE}.AcknowledgementEmailService"):
            self.svc.send_acknowledgement(mi)
        self.assertTrue(mi.user_reception_informed)

    def test_final_failure_propagates_the_original_error(self):
        mi = self._mail()
        with patch(f"{BASE}.FinalEmailService") as svc:
            svc.return_value._send_action.side_effect = OSError("relay down")
            with self.assertRaises(OSError):
                self.svc.send_final(mi, MagicMock(id=7, results="Safe"))
        self.assertFalse(mi.user_analysis_informed)

    def test_review_failure_propagates(self):
        case = MagicMock(id=7, results="Dangerous", reporter=self.user)
        with patch(f"{BASE}.ModificationEmailService") as svc:
            svc.return_value._send_action.side_effect = OSError("relay down")
            with self.assertRaises(OSError):
                self.svc.send_review_email(case)
