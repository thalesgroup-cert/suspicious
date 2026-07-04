from io import StringIO

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase

from case_handler.models import Case
from cortex_job.models import Analyzer, AnalyzerReport, CaseAnalyzerJob
from ip_process.models import IP


class BacktestTest(TestCase):
    def test_runs_read_only(self):
        user = get_user_model().objects.create_user(username="bt_u", password="x")
        case = Case.objects.create(description="", reporter=user, results="Suspicious")
        out = StringIO()
        call_command("backtest_scoring", stdout=out)
        case.refresh_from_db()
        self.assertEqual(case.results, "Suspicious")   # unchanged — read-only
        self.assertIn("old", out.getvalue().lower())    # header printed

    def test_reports_drift(self):
        # A case stored as "Safe" whose ledger report is malicious must show up
        # as a Safe -> Dangerous transition, proving the drift table is real.
        user = get_user_model().objects.create_user(username="bt_d", password="x")
        case = Case.objects.create(description="", reporter=user, results="Safe")
        ip = IP.objects.create(address="203.0.113.9")
        analyzer = Analyzer.objects.create(name="Abuse", analyzer_cortex_id="Abuse", weight=1)
        report = AnalyzerReport.objects.create(
            cortex_job_id="bt1", type="ip", status="Success", analyzer=analyzer,
            ip=ip, level="malicious", confidence=100, score=9,
            report_summary={}, report_taxonomy={}, report_full={},
        )
        CaseAnalyzerJob.objects.create(
            case=case, cortex_job_id="bt1", analyzer=analyzer,
            analyzer_report=report, status="Success",
        )
        out = StringIO()
        call_command("backtest_scoring", stdout=out)
        text = out.getvalue()
        self.assertIn("Safe -> Dangerous", text)
        self.assertIn("CHANGED", text)
        case.refresh_from_db()
        self.assertEqual(case.results, "Safe")   # still read-only
