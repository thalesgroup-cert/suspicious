from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase

from case_handler.models import Case
from cortex_job.models import Analyzer, AnalyzerReport, CaseAnalyzerJob
from tasp.tasks import process_cortex_job


class ProcessCortexJobTest(TestCase):
    def setUp(self):
        cache.clear()
        User = get_user_model()
        self.reporter = User.objects.create_user(
            username="process_cortex_job_user", password="x"
        )
        self.case = Case.objects.create(
            status="On Going", description="", reporter=self.reporter
        )
        self.analyzer = Analyzer.objects.create(
            name="A1", analyzer_cortex_id="c1"
        )
        self.ar = AnalyzerReport.objects.create(
            cortex_job_id="job-1",
            type="ip",
            analyzer=self.analyzer,
            status="InProgress",
            level="info",
            confidence=0,
            score=0,
            report_summary={},
            report_taxonomy={},
            report_full={},
        )
        self.caj = CaseAnalyzerJob.objects.create(
            case=self.case,
            cortex_job_id="job-1",
            analyzer=self.analyzer,
            analyzer_report=self.ar,
            status=CaseAnalyzerJob.STATUS_INPROGRESS,
        )

    @patch(
        "cortex_job.cortex_utils.cortex_and_job_management."
        "CortexJobManager.finalise_case"
    )
    @patch(
        "cortex_job.cortex_utils.cortex_and_job_management."
        "CortexJobManager.update_single_job"
    )
    def test_happy_path_calls_update_then_finalise(self, mock_update, mock_finalise):
        # update_single_job marks the CAJ as Success so pending count drops to 0
        def mark_success(caj):
            caj.status = CaseAnalyzerJob.STATUS_SUCCESS
            caj.save(update_fields=["status"])
        mock_update.side_effect = mark_success

        process_cortex_job.apply(args=[self.case.id, "job-1"]).get()

        mock_update.assert_called_once()
        mock_finalise.assert_called_once()

    @patch(
        "cortex_job.cortex_utils.cortex_and_job_management."
        "CortexJobManager.update_single_job"
    )
    def test_lock_contention_returns_early(self, mock_update):
        cache.add(f"case_update_lock:{self.case.id}", 1, timeout=60)
        try:
            process_cortex_job.apply(args=[self.case.id, "job-1"]).get()
            mock_update.assert_not_called()
        finally:
            cache.delete(f"case_update_lock:{self.case.id}")

    @patch(
        "cortex_job.cortex_utils.cortex_and_job_management."
        "CortexJobManager.update_single_job"
    )
    def test_already_finalised_short_circuits(self, mock_update):
        self.caj.status = CaseAnalyzerJob.STATUS_SUCCESS
        self.caj.save(update_fields=["status"])
        process_cortex_job.apply(args=[self.case.id, "job-1"]).get()
        mock_update.assert_not_called()

    def test_missing_caj_returns_silently(self):
        # No matching CAJ — should log and return, not raise.
        process_cortex_job.apply(
            args=[self.case.id, "job-does-not-exist"]
        ).get()

    @patch(
        "cortex_job.cortex_utils.cortex_and_job_management."
        "CortexJobManager.finalise_case"
    )
    @patch(
        "cortex_job.cortex_utils.cortex_and_job_management."
        "CortexJobManager.update_single_job"
    )
    def test_remaining_pending_skips_finalise(self, mock_update, mock_finalise):
        """If another CAJ is still pending, finalise_case must NOT run."""
        # Second pending CAJ on the same case
        ar2 = AnalyzerReport.objects.create(
            cortex_job_id="job-2",
            type="ip",
            analyzer=self.analyzer,
            status="InProgress",
            level="info",
            confidence=0,
            score=0,
            report_summary={},
            report_taxonomy={},
            report_full={},
        )
        CaseAnalyzerJob.objects.create(
            case=self.case,
            cortex_job_id="job-2",
            analyzer=self.analyzer,
            analyzer_report=ar2,
            status=CaseAnalyzerJob.STATUS_INPROGRESS,
        )

        def mark_success(caj):
            caj.status = CaseAnalyzerJob.STATUS_SUCCESS
            caj.save(update_fields=["status"])
        mock_update.side_effect = mark_success

        process_cortex_job.apply(args=[self.case.id, "job-1"]).get()

        mock_update.assert_called_once()
        mock_finalise.assert_not_called()
