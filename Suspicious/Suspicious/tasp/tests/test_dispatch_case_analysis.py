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


class DispatchMailIntentsTest(TestCase):
    """The web mail upload hands its whole launch list to this task."""

    def setUp(self):
        user = get_user_model().objects.create_user(username="dmi_u", password="x")
        self.case = Case.objects.create(description="", reporter=user)
        self.ip = IP.objects.create(address="203.0.113.9")

    @patch("tasp.tasks.reconcile_case.delay")
    @patch("cortex_job.cortex_utils.cortex_and_job_management.CortexJob")
    def test_path_intent_is_passed_through_as_a_plain_value(self, mock_cortex_cls, mock_reconcile):
        mock_cortex = mock_cortex_cls.return_value

        dispatch_case_analysis.run(self.case.id, [("__path__", "/tmp/m/body.txt", "mail_body")])

        mock_cortex.launch_cortex_jobs.assert_called_once_with(
            value="/tmp/m/body.txt", data_type="mail_body", case=self.case
        )

    @patch("tasp.tasks.reconcile_case.delay")
    @patch("cortex_job.cortex_utils.cortex_and_job_management.CortexJob")
    def test_ai_archive_intent_runs_the_ai_job_last(self, mock_cortex_cls, mock_reconcile):
        mock_cortex = mock_cortex_cls.return_value
        calls = []
        mock_cortex.launch_cortex_jobs.side_effect = lambda **kw: calls.append("jobs")
        mock_cortex.launch_cortex_ai_jobs.side_effect = lambda *a, **kw: calls.append("ai")
        intents = [
            ("ip_process.ip", self.ip.pk, "ai_archive"),
            ("ip_process.ip", self.ip.pk, "ip"),
        ]

        dispatch_case_analysis.run(self.case.id, intents)

        mock_cortex.launch_cortex_ai_jobs.assert_called_once_with(self.ip, "file", case=self.case)
        self.assertEqual(calls, ["jobs", "ai"])
        mock_reconcile.assert_called_once_with(self.case.id)

    @patch("tasp.tasks.reconcile_case.delay")
    @patch("cortex_job.cortex_utils.cortex_and_job_management.CortexJob")
    def test_ai_job_failure_still_marks_the_case_dispatched(self, mock_cortex_cls, mock_reconcile):
        mock_cortex_cls.return_value.launch_cortex_ai_jobs.side_effect = RuntimeError("boom")

        dispatch_case_analysis.run(self.case.id, [("ip_process.ip", self.ip.pk, "ai_archive")])

        self.case.refresh_from_db()
        self.assertIsNotNone(self.case.dispatched_at)
        mock_reconcile.assert_called_once_with(self.case.id)

    @patch("tasp.tasks.reconcile_case.delay")
    @patch("cortex_job.cortex_utils.cortex_and_job_management.CortexJob")
    def test_sender_domain_is_used_only_when_asked(self, mock_cortex_cls, mock_reconcile):
        intents = [("ip_process.ip", self.ip.pk, "ip")]
        with patch("url_process.url_utils.url_planner.filter_dispatch_intents", side_effect=lambda i, **kw: i) as flt, \
             patch("mail_feeder.job_handler.artifacts.artifacts._sender_domain_for_case", return_value="corp.example"):
            dispatch_case_analysis.run(self.case.id, intents)
            self.assertIsNone(flt.call_args.kwargs["sender_domain"])
            dispatch_case_analysis.run(self.case.id, intents, use_sender_domain=True)
            self.assertEqual(flt.call_args.kwargs["sender_domain"], "corp.example")


class DispatchReopensPrematureCaseTest(TestCase):
    """A case finalised before its jobs were launched is reopened so they count."""

    def setUp(self):
        user = get_user_model().objects.create_user(username="dro_u", password="x")
        self.case = Case.objects.create(description="", reporter=user)
        self.ip = IP.objects.create(address="203.0.113.11")

    def _finalise_empty(self):
        from case_handler.lifecycle import LifecycleState
        self.case.lifecycle_state = LifecycleState.FINALIZED
        self.case.results = "Failure"
        self.case.save(update_fields=["lifecycle_state", "results"])

    @patch("tasp.tasks.reconcile_case.delay")
    @patch("cortex_job.cortex_utils.cortex_and_job_management.CortexJob")
    def test_finalised_without_dispatch_is_reopened_before_launching(self, mock_cortex_cls, mock_reconcile):
        from case_handler.lifecycle import LifecycleState
        self._finalise_empty()
        states = []
        mock_cortex_cls.return_value.launch_cortex_jobs.side_effect = (
            lambda **kw: states.append(Case.objects.get(pk=self.case.pk).lifecycle_state)
        )

        dispatch_case_analysis.run(self.case.id, [("ip_process.ip", self.ip.pk, "ip")])

        self.assertEqual(states, [LifecycleState.ANALYZING])
        self.case.refresh_from_db()
        self.assertEqual(self.case.results, "Inconclusive")
        mock_reconcile.assert_called_once_with(self.case.id)

    @patch("tasp.tasks.reconcile_case.delay")
    @patch("cortex_job.cortex_utils.cortex_and_job_management.CortexJob")
    def test_finalised_case_is_reopened_even_when_a_launch_time_was_recorded(self, mock_cortex_cls, mock_reconcile):
        """An empty dispatch can stamp dispatched_at and finalise the case first; the jobs of
        the real launch still have to count."""
        from django.utils import timezone
        from case_handler.lifecycle import LifecycleState
        self._finalise_empty()
        self.case.dispatched_at = timezone.now()
        self.case.save(update_fields=["dispatched_at"])
        states = []
        mock_cortex_cls.return_value.launch_cortex_jobs.side_effect = (
            lambda **kw: states.append(Case.objects.get(pk=self.case.pk).lifecycle_state)
        )

        dispatch_case_analysis.run(self.case.id, [("ip_process.ip", self.ip.pk, "ip")])

        self.assertEqual(states, [LifecycleState.ANALYZING])

    @patch("tasp.tasks.reconcile_case.delay")
    @patch("cortex_job.cortex_utils.cortex_and_job_management.CortexJob")
    def test_dispatch_with_nothing_to_launch_leaves_a_finalised_case_alone(self, mock_cortex_cls, mock_reconcile):
        from django.utils import timezone
        from case_handler.lifecycle import LifecycleState
        self._finalise_empty()
        self.case.dispatched_at = timezone.now()
        self.case.save(update_fields=["dispatched_at"])

        dispatch_case_analysis.run(self.case.id, [])

        self.case.refresh_from_db()
        self.assertEqual(self.case.lifecycle_state, LifecycleState.FINALIZED)
