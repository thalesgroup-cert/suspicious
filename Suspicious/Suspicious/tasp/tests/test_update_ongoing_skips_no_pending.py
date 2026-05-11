from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase
from case_handler.models import Case
from cortex_job.models import Analyzer, CaseAnalyzerJob
from tasp.cron.user_and_cases import update_ongoing_case_jobs


class UpdateOngoingSkipsNoPendingTest(TestCase):
    def setUp(self):
        cache.clear()
        User = get_user_model()
        self.reporter = User.objects.create_user(
            username="cron_skip_user", password="x"
        )
        self.analyzer = Analyzer.objects.create(
            name="A1", analyzer_cortex_id="c1"
        )

    @patch(
        "cortex_job.cortex_utils.cortex_and_job_management."
        "CortexJobManager.manage_jobs"
    )
    def test_case_with_no_pending_caj_is_skipped(self, mock_manage):
        case = Case.objects.create(
            status="On Going", description="", reporter=self.reporter
        )
        # Only Done CAJ — no pending
        CaseAnalyzerJob.objects.create(
            case=case,
            cortex_job_id="j",
            analyzer=self.analyzer,
            status=CaseAnalyzerJob.STATUS_SUCCESS,
        )
        update_ongoing_case_jobs()
        mock_manage.assert_not_called()

    @patch(
        "cortex_job.cortex_utils.cortex_and_job_management."
        "CortexJobManager.manage_jobs"
    )
    def test_case_with_pending_caj_is_processed(self, mock_manage):
        case = Case.objects.create(
            status="On Going", description="", reporter=self.reporter
        )
        CaseAnalyzerJob.objects.create(
            case=case,
            cortex_job_id="j",
            analyzer=self.analyzer,
            status=CaseAnalyzerJob.STATUS_INPROGRESS,
        )
        update_ongoing_case_jobs()
        mock_manage.assert_called_once()

    @patch(
        "cortex_job.cortex_utils.cortex_and_job_management."
        "CortexJobManager.manage_jobs"
    )
    def test_case_with_no_caj_is_skipped(self, mock_manage):
        Case.objects.create(
            status="On Going", description="", reporter=self.reporter
        )
        update_ongoing_case_jobs()
        mock_manage.assert_not_called()
