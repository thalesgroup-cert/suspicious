"""Unit + integration tests for the Cortex scoring pipeline."""
from datetime import timedelta
from unittest.mock import MagicMock, patch

from django.test import TestCase
from django.utils import timezone

from cortex_job.cortex_utils.cortex_and_job_management import (
    CortexJob,
    CortexJobManager,
)
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


class GetNewReportsTests(TestCase):
    def setUp(self):
        self.analyzer = Analyzer.objects.create(
            analyzer_cortex_id="vt-1",
            name="VirusTotal_GetReport_3_1",
            weight=0.2,
        )
        self.domain = Domain.objects.create(value="example.com")
        self.manager = CortexJobManager()
        self.manager.case = MagicMock(id=42)

    def _make_report(self, status, days_old=0):
        report = AnalyzerReport.objects.create(
            cortex_job_id=f"job-{status}-{days_old}",
            type="domain",
            status=status,
            analyzer=self.analyzer,
            domain=self.domain,
            level="info",
            confidence=0,
            score=0,
            report_summary={},
            report_full={},
            report_taxonomy={},
        )
        if days_old:
            AnalyzerReport.objects.filter(pk=report.pk).update(
                creation_date=timezone.now() - timedelta(days=days_old)
            )
            report.refresh_from_db()
        return report

    def test_returns_old_inprogress_report(self):
        old = self._make_report("InProgress", days_old=7)
        result = list(self.manager.get_new_reports("domain", {"domain": self.domain}))
        self.assertIn(old, result)

    def test_excludes_deleted_reports(self):
        deleted = self._make_report("Deleted")
        result = list(self.manager.get_new_reports("domain", {"domain": self.domain}))
        self.assertNotIn(deleted, result)

    def test_returns_success_reports(self):
        ok = self._make_report("Success", days_old=3)
        result = list(self.manager.get_new_reports("domain", {"domain": self.domain}))
        self.assertIn(ok, result)
