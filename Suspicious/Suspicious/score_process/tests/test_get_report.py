"""End-to-end integration test for the rewired scoring entrypoint.

Every other finalise test mocks CortexAnalyzerReports.get_report, so nothing
exercises the real collect_signals → score_case → apply_verdict wiring. A prior
branch review found a bug hiding in exactly this mock-covered seam, so this
test drives the real get_report and asserts the verdict lands on the Case.
"""
from django.contrib.auth import get_user_model
from django.test import TestCase

from case_handler.models import Case, CaseHasNonFileIocs, Result
from cortex_job.models import Analyzer, AnalyzerReport
from ip_process.models import IP
from score_process.scoring.cortex_analyzers.reports import CortexAnalyzerReports


class GetReportIntegrationTest(TestCase):
    def test_malicious_ioc_case_scores_dangerous_end_to_end(self):
        user = get_user_model().objects.create_user(username="gr_u", password="x")
        # Same fixture shape as test_collect: the report's score/confidence are
        # re-derived from the taxonomy level by the analyzer pipeline, so a
        # "malicious" taxonomy is what yields score=10/conf=100 downstream.
        ip = IP.objects.create(address="203.0.113.8")
        analyzer = Analyzer.objects.create(name="Abuse", analyzer_cortex_id="Abuse", weight=1)
        AnalyzerReport.objects.create(
            cortex_job_id="gr1", type="ip", status="Success", analyzer=analyzer,
            ip=ip, level="malicious", confidence=9, score=9,
            report_summary={"taxonomies": [{"level": "malicious", "value": "abuse"}]},
            report_taxonomy={}, report_full={},
        )
        case = Case.objects.create(description="", reporter=user)
        iocs = CaseHasNonFileIocs.objects.create(case=case, ip=ip)
        case.nonFileIocs = iocs
        case.save()

        CortexAnalyzerReports.get_report(case)

        case.refresh_from_db()
        # One malicious IOC → malicious-vote override (1 >= max(1, 1//3)) → Dangerous.
        self.assertEqual(case.results, Result.DANGEROUS)
        self.assertEqual(case.final_score, 10)
        self.assertGreaterEqual(case.analysis_done, 1)
        self.assertTrue(case.kpi_counted)   # apply_verdict ran through to KPI
