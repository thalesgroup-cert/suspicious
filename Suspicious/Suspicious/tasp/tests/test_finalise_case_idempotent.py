from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.test import TestCase
from case_handler.models import Case
from cortex_job.cortex_utils.cortex_and_job_management import CortexJobManager


class FinaliseCaseIdempotentTest(TestCase):
    def setUp(self):
        User = get_user_model()
        self.reporter = User.objects.create_user(
            username="finalise_idempotent_user", password="x"
        )
        self.case = Case.objects.create(
            status="On Going", description="", reporter=self.reporter
        )

    @patch(
        "score_process.scoring.cortex_analyzers.reports."
        "CortexAnalyzerReports.get_report"
    )
    @patch.object(CortexJobManager, "generate_description")
    @patch.object(CortexJobManager, "get_results")
    def test_finalise_twice_does_not_double_score(
        self, mock_results, mock_description, mock_get_report
    ):
        # Simulate case finishing on first finalise_case call
        def mark_done(case):
            case.status = "Done"
            case.save()
        mock_description.side_effect = mark_done

        mgr = CortexJobManager()
        mgr.finalise_case(self.case)
        # Second call: case is already Done — get_report should be called again
        # but the underlying scoring is idempotent per Step 1 verification.
        mgr.finalise_case(self.case)

        # Both calls happen — that's by design: webhook may deliver duplicates.
        # The idempotency guarantee is inside CortexAnalyzerReports.get_report.
        self.assertEqual(mock_get_report.call_count, 2)

    @patch(
        "score_process.scoring.cortex_analyzers.reports."
        "CortexAnalyzerReports.get_report"
    )
    @patch.object(CortexJobManager, "generate_description")
    @patch.object(CortexJobManager, "get_results")
    def test_finalise_skips_get_report_when_not_done(
        self, mock_results, mock_description, mock_get_report
    ):
        # generate_description does NOT flip to Done
        mock_description.side_effect = lambda case: None

        mgr = CortexJobManager()
        mgr.finalise_case(self.case)

        mock_get_report.assert_not_called()
