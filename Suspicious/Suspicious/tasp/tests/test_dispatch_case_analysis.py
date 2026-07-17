from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.test import TestCase

from case_handler.models import Case
from ip_process.models import IP
from tasp.tasks import dispatch_case_analysis


class DispatchCaseAnalysisTaskTest(TestCase):
    def setUp(self):
        user = get_user_model().objects.create_user(username="dca_u", password="x")
        self.case = Case.objects.create(description="", reporter=user)
        self.ip = IP.objects.create(address="203.0.113.5")

    @patch("tasp.tasks.reconcile_case.delay")
    @patch("cortex_job.cortex_utils.cortex_and_job_management.CortexJob")
    def test_resolves_intents_and_launches_analysis(self, mock_cortex_cls, mock_reconcile):
        mock_cortex = mock_cortex_cls.return_value
        intents = [("ip_process.ip", self.ip.pk, "ip")]

        dispatch_case_analysis.run(self.case.id, intents)

        mock_cortex.launch_cortex_jobs.assert_called_once_with(
            value=self.ip, data_type="ip", case=self.case
        )
        mock_reconcile.assert_called_once_with(self.case.id)
        self.case.refresh_from_db()
        self.assertIsNotNone(self.case.dispatched_at)

    @patch("tasp.tasks.reconcile_case.delay")
    @patch("cortex_job.cortex_utils.cortex_and_job_management.CortexJob")
    def test_missing_case_is_noop(self, mock_cortex_cls, mock_reconcile):
        dispatch_case_analysis.run(999999, [])

        mock_cortex_cls.assert_not_called()
        mock_reconcile.assert_not_called()

    @patch("tasp.tasks.reconcile_case.delay")
    @patch("cortex_job.cortex_utils.cortex_and_job_management.CortexJob")
    def test_unresolvable_intent_is_skipped_without_blocking_others(
        self, mock_cortex_cls, mock_reconcile
    ):
        mock_cortex = mock_cortex_cls.return_value
        intents = [
            ("ip_process.ip", 999999, "ip"),  # no longer exists
            ("ip_process.ip", self.ip.pk, "ip"),
        ]

        dispatch_case_analysis.run(self.case.id, intents)

        mock_cortex.launch_cortex_jobs.assert_called_once_with(
            value=self.ip, data_type="ip", case=self.case
        )
        mock_reconcile.assert_called_once_with(self.case.id)

    @patch("tasp.tasks.reconcile_case.delay")
    @patch("cortex_job.cortex_utils.cortex_and_job_management.CortexJob")
    def test_per_intent_failure_does_not_block_others(self, mock_cortex_cls, mock_reconcile):
        mock_cortex = mock_cortex_cls.return_value
        mock_cortex.launch_cortex_jobs.side_effect = [Exception("boom"), None]
        other_ip = IP.objects.create(address="198.51.100.7")
        intents = [
            ("ip_process.ip", self.ip.pk, "ip"),
            ("ip_process.ip", other_ip.pk, "ip"),
        ]

        dispatch_case_analysis.run(self.case.id, intents)

        self.assertEqual(mock_cortex.launch_cortex_jobs.call_count, 2)
        mock_reconcile.assert_called_once_with(self.case.id)
