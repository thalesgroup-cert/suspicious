"""The cron fallback must keep the CaseAnalyzerJob ledger in sync.

Regression guard: `update_ongoing_case_jobs` used to call `manage_jobs`,
which updates AnalyzerReport rows + the case but never the CaseAnalyzerJob
ledger. When the Cortex webhook does not fire (so the cron is the only
path that runs), this left ledger rows stuck `InProgress` forever even
after the case finalised — and `fail_stale_jobs` would later mis-mark
those succeeded jobs as Failed at the 24h timeout.

The fallback must mirror the webhook task `process_cortex_job`: sync each
pending CaseAnalyzerJob via `update_single_job`, then `finalise_case`
once no pending rows remain.
"""
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase

from case_handler.models import Case
from cortex_job.models import Analyzer, AnalyzerReport, CaseAnalyzerJob
from tasp.cron.user_and_cases import update_ongoing_case_jobs


class UpdateOngoingSyncsLedgerTest(TestCase):
    def setUp(self):
        cache.clear()
        User = get_user_model()
        self.reporter = User.objects.create_user(
            username="cron_ledger_user", password="x"
        )
        self.analyzer = Analyzer.objects.create(name="A1", analyzer_cortex_id="c1")
        self.case = Case.objects.create(
            status="On Going", description="", reporter=self.reporter
        )
        self.ar = AnalyzerReport.objects.create(
            cortex_job_id="job-1", type="ip", analyzer=self.analyzer,
            status="InProgress", level="info", confidence=0, score=0,
            report_summary={}, report_taxonomy={}, report_full={},
        )
        self.caj = CaseAnalyzerJob.objects.create(
            case=self.case, cortex_job_id="job-1", analyzer=self.analyzer,
            analyzer_report=self.ar, status=CaseAnalyzerJob.STATUS_INPROGRESS,
        )

    @patch(
        "cortex_job.cortex_utils.cortex_and_job_management."
        "CortexJobManager.finalise_case"
    )
    @patch(
        "cortex_job.cortex_utils.cortex_and_job_management."
        "CortexJobManager.update_single_job"
    )
    def test_fallback_syncs_ledger_then_finalises(self, mock_update, mock_finalise):
        def mark_success(caj):
            caj.status = CaseAnalyzerJob.STATUS_SUCCESS
            caj.save(update_fields=["status"])

        mock_update.side_effect = mark_success

        update_ongoing_case_jobs()

        # Ledger row was synced (not left InProgress) ...
        mock_update.assert_called_once()
        self.caj.refresh_from_db()
        self.assertEqual(self.caj.status, CaseAnalyzerJob.STATUS_SUCCESS)
        # ... and the case finalised once the last pending row settled.
        mock_finalise.assert_called_once()

    @patch(
        "cortex_job.cortex_utils.cortex_and_job_management."
        "CortexJobManager.finalise_case"
    )
    @patch(
        "cortex_job.cortex_utils.cortex_and_job_management."
        "CortexJobManager.update_single_job"
    )
    def test_remaining_pending_skips_finalise(self, mock_update, mock_finalise):
        ar2 = AnalyzerReport.objects.create(
            cortex_job_id="job-2", type="ip", analyzer=self.analyzer,
            status="InProgress", level="info", confidence=0, score=0,
            report_summary={}, report_taxonomy={}, report_full={},
        )
        CaseAnalyzerJob.objects.create(
            case=self.case, cortex_job_id="job-2", analyzer=self.analyzer,
            analyzer_report=ar2, status=CaseAnalyzerJob.STATUS_INPROGRESS,
        )

        # Only the first job settles; the second stays pending.
        def mark_first_only(caj):
            if caj.cortex_job_id == "job-1":
                caj.status = CaseAnalyzerJob.STATUS_SUCCESS
                caj.save(update_fields=["status"])

        mock_update.side_effect = mark_first_only

        update_ongoing_case_jobs()

        self.assertEqual(mock_update.call_count, 2)
        mock_finalise.assert_not_called()
