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
from url_process.models import URL
from ip_process.models import IP
from hash_process.models import Hash
from email_process.models import MailAddress


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


class ArtifactValueTests(TestCase):
    def setUp(self):
        self.analyzer = Analyzer.objects.create(
            analyzer_cortex_id="any", name="any", weight=0.2,
        )

    def _make_report(self, **fk):
        return AnalyzerReport.objects.create(
            cortex_job_id="job-art",
            type="any",
            status="Success",
            analyzer=self.analyzer,
            level="info",
            confidence=0,
            score=0,
            report_summary={},
            report_full={},
            report_taxonomy={},
            **fk,
        )

    def test_domain_value(self):
        d = Domain.objects.create(value="example.com")
        r = self._make_report(domain=d)
        self.assertEqual(CortexJobManager._artifact_value(r), "example.com")

    def test_url_address(self):
        u = URL.objects.create(address="https://example.com/x")
        r = self._make_report(url=u)
        self.assertEqual(CortexJobManager._artifact_value(r), "https://example.com/x")

    def test_ip_address(self):
        ip = IP.objects.create(address="1.2.3.4")
        r = self._make_report(ip=ip)
        self.assertEqual(CortexJobManager._artifact_value(r), "1.2.3.4")

    def test_hash_value(self):
        h = Hash.objects.create(value="deadbeef")
        r = self._make_report(hash=h)
        self.assertEqual(CortexJobManager._artifact_value(r), "deadbeef")

    def test_mail_address(self):
        m = MailAddress.objects.create(address="a@b.com")
        r = self._make_report(mail=m)
        self.assertEqual(CortexJobManager._artifact_value(r), "a@b.com")

    def test_orphan_raises(self):
        r = self._make_report()
        with self.assertRaises(ValueError):
            CortexJobManager._artifact_value(r)
