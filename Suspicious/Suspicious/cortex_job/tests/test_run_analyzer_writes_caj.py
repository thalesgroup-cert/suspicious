from unittest.mock import MagicMock, patch
from django.test import TestCase
from django.contrib.auth import get_user_model
from cortex_job.cortex_utils.cortex_and_job_management import CortexJob
from cortex_job.models import Analyzer, AnalyzerReport, CaseAnalyzerJob
from case_handler.models import Case
from ip_process.models import IP


class RunAnalyzerWritesCAJ(TestCase):
    def setUp(self):
        User = get_user_model()
        self.reporter = User.objects.create_user(
            username="run_analyzer_reporter", password="x"
        )
        self.case = Case.objects.create(
            status="On Going", description="", reporter=self.reporter
        )
        self.ip = IP.objects.create(address="1.2.3.4")
        self.cortex_analyzer = MagicMock(id="c1")
        self.cortex_analyzer.name = "A1"

    def test_writes_both_rows(self):
        api = MagicMock()
        report_mock = MagicMock(id="job-99")
        api.analyzers.run_by_name.return_value = report_mock

        result = CortexJob.run_analyzer(api, self.cortex_analyzer, self.ip, "ip", self.case)

        self.assertEqual(result, report_mock)
        ar = AnalyzerReport.objects.get(cortex_job_id="job-99")
        caj = CaseAnalyzerJob.objects.get(cortex_job_id="job-99")
        self.assertEqual(caj.case_id, self.case.id)
        self.assertEqual(caj.analyzer_report_id, ar.id)
        self.assertEqual(caj.status, CaseAnalyzerJob.STATUS_INPROGRESS)

    def test_case_required(self):
        api = MagicMock()
        api.analyzers.run_by_name.return_value = MagicMock(id="job-x")
        with self.assertRaises(TypeError):
            CortexJob.run_analyzer(api, self.cortex_analyzer, self.ip, "ip", None)

    def test_rollback_on_caj_failure(self):
        """If CaseAnalyzerJob.create raises, AnalyzerReport must not persist."""
        api = MagicMock()
        api.analyzers.run_by_name.return_value = MagicMock(id="job-77")

        with patch.object(
            CaseAnalyzerJob.objects, "create", side_effect=RuntimeError("boom")
        ):
            with self.assertRaises(RuntimeError):
                CortexJob.run_analyzer(api, self.cortex_analyzer, self.ip, "ip", self.case)

        self.assertFalse(AnalyzerReport.objects.filter(cortex_job_id="job-77").exists())
