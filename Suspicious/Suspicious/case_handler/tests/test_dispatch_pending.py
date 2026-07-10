from unittest.mock import MagicMock, patch
from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase

from case_handler.case_utils.case_handler import CaseHandler
from case_handler.models import Case


class CaseHandlerDispatchPendingTest(TestCase):
    def setUp(self):
        User = get_user_model()
        self.reporter = User.objects.create_user(
            username="dispatch_pending_user", password="x"
        )
        self.case = Case.objects.create(
            status="On Going", description="", reporter=self.reporter
        )
        request = RequestFactory().post("/api/submit")
        request.user = self.reporter
        self.handler = CaseHandler(request, MagicMock(), MagicMock(), MagicMock())
        self.handler.pending_dispatch_intents = [
            ("artifact-1", "ip"),
            ("artifact-2", "url"),
        ]

    @patch("case_handler.case_utils.case_handler.CortexJob")
    def test_dispatches_each_intent_with_case(self, mock_cortex_cls):
        mock_cortex = mock_cortex_cls.return_value
        self.handler.dispatch_pending(self.case)

        self.assertEqual(mock_cortex.launch_cortex_jobs.call_count, 2)
        mock_cortex.launch_cortex_jobs.assert_any_call(
            value="artifact-1", data_type="ip", case=self.case
        )
        mock_cortex.launch_cortex_jobs.assert_any_call(
            value="artifact-2", data_type="url", case=self.case
        )
        self.assertEqual(self.handler.pending_dispatch_intents, [])

    @patch("case_handler.case_utils.case_handler.CortexJob")
    def test_none_case_drops_intents_with_warning(self, mock_cortex_cls):
        with self.assertLogs("case_handler.case_utils.case_handler", level="WARNING") as cm:
            self.handler.dispatch_pending(None)

        mock_cortex_cls.return_value.launch_cortex_jobs.assert_not_called()
        self.assertEqual(self.handler.pending_dispatch_intents, [])
        self.assertTrue(any("Dropping 2 pending" in m for m in cm.output))

    @patch("case_handler.case_utils.case_handler.CortexJob")
    def test_per_intent_failure_does_not_block_others(self, mock_cortex_cls):
        mock_cortex = mock_cortex_cls.return_value
        mock_cortex.launch_cortex_jobs.side_effect = [Exception("boom"), None]
        self.handler.dispatch_pending(self.case)

        self.assertEqual(mock_cortex.launch_cortex_jobs.call_count, 2)
        self.assertEqual(self.handler.pending_dispatch_intents, [])

    @patch("case_handler.case_utils.case_handler.CortexJob")
    def test_second_call_is_noop(self, mock_cortex_cls):
        mock_cortex = mock_cortex_cls.return_value
        self.handler.dispatch_pending(self.case)
        self.handler.dispatch_pending(self.case)
        self.assertEqual(mock_cortex.launch_cortex_jobs.call_count, 2)
