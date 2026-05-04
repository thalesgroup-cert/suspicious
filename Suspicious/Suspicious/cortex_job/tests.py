"""Unit + integration tests for the Cortex scoring pipeline."""
from unittest.mock import MagicMock, patch

from django.test import TestCase

from cortex_job.cortex_utils.cortex_and_job_management import CortexJob
from cortex_job.models import Analyzer, AnalyzerReport
from domain_process.models import Domain


class RunAnalyzerStatusTests(TestCase):
    def test_run_analyzer_creates_report_with_inprogress_status(self):
        analyzer = MagicMock()
        analyzer.id = "ana-1"
        analyzer.name = "VirusTotal_GetReport_3_1"

        domain = Domain.objects.create(value="example.com")

        api = MagicMock()
        report_obj = MagicMock()
        report_obj.id = "job-xyz"
        api.analyzers.run_by_name.return_value = report_obj

        result = CortexJob.run_analyzer(api, analyzer, domain, "domain")

        self.assertIsNotNone(result)
        row = AnalyzerReport.objects.get(cortex_job_id="job-xyz")
        self.assertEqual(row.status, "InProgress")
