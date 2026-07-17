from unittest.mock import MagicMock, patch
from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase

from case_handler.case_utils.case_handler import CaseHandler
from case_handler.models import Case
from ip_process.models import IP
from url_process.models import URL


class CaseHandlerDispatchPendingTest(TestCase):
    def setUp(self):
        User = get_user_model()
        self.reporter = User.objects.create_user(
            username="dispatch_pending_user", password="x"
        )
        self.case = Case.objects.create(
            status="On Going", description="", reporter=self.reporter
        )
        self.ip = IP.objects.create(address="203.0.113.5")
        self.url = URL.objects.create(address="http://example.test/phish")
        request = RequestFactory().post("/api/submit")
        request.user = self.reporter
        self.handler = CaseHandler(request, MagicMock(), MagicMock(), MagicMock())
        self.handler.pending_dispatch_intents = [
            (self.ip, "ip"),
            (self.url, "url"),
        ]

    @patch("tasp.tasks.dispatch_case_analysis.delay")
    def test_queues_async_dispatch_with_serialized_intents(self, mock_delay):
        with self.captureOnCommitCallbacks(execute=True):
            self.handler.dispatch_pending(self.case)

        expected_intents = [
            (f"{self.ip._meta.app_label}.{self.ip._meta.model_name}", self.ip.pk, "ip"),
            (f"{self.url._meta.app_label}.{self.url._meta.model_name}", self.url.pk, "url"),
        ]
        mock_delay.assert_called_once_with(self.case.id, expected_intents)
        self.assertEqual(self.handler.pending_dispatch_intents, [])

    @patch("tasp.tasks.dispatch_case_analysis.delay")
    def test_none_case_drops_intents_with_warning(self, mock_delay):
        with self.assertLogs("case_handler.case_utils.case_handler", level="WARNING") as cm:
            self.handler.dispatch_pending(None)

        mock_delay.assert_not_called()
        self.assertEqual(self.handler.pending_dispatch_intents, [])
        self.assertTrue(any("Dropping 2 pending" in m for m in cm.output))

    @patch("tasp.tasks.dispatch_case_analysis.delay")
    def test_second_call_is_noop(self, mock_delay):
        with self.captureOnCommitCallbacks(execute=True):
            self.handler.dispatch_pending(self.case)
        self.handler.dispatch_pending(self.case)

        mock_delay.assert_called_once()

    @patch("tasp.tasks.dispatch_case_analysis.delay")
    def test_not_queued_without_transaction_commit(self, mock_delay):
        # dispatch_pending schedules via transaction.on_commit; outside of a
        # commit (e.g. the surrounding test transaction rolling back) the
        # task must never fire.
        self.handler.dispatch_pending(self.case)
        mock_delay.assert_not_called()
