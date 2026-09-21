"""End-to-end integration test for the rewired scoring entrypoint.

Every other finalise test mocks CortexAnalyzerReports.get_report, so nothing
exercises the real collect_signals → score_case → apply_verdict wiring. A prior
branch review found a bug hiding in exactly this mock-covered seam, so this
test drives the real get_report and asserts the verdict lands on the Case.
"""
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from case_handler.models import Case, CaseHasFileOrMail, CaseHasNonFileIocs, Result
from cortex_job.models import Analyzer, AnalyzerReport
from file_process.models import File
from hash_process.models import Hash
from ip_process.models import IP
from mail_feeder.models import Mail, MailArchive
from score_process.scoring.cortex_analyzers.reports import CortexAnalyzerReports


class GetReportIntegrationTest(TestCase):
    def test_malicious_ioc_case_scores_dangerous_end_to_end(self):
        user = get_user_model().objects.create_user(username="gr_u", password="x")
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
        self.assertEqual(case.results, Result.DANGEROUS)
        self.assertEqual(case.final_score, 10)
        self.assertGreaterEqual(case.analysis_done, 1)
        self.assertTrue(case.kpi_counted)

    def test_mail_case_still_scores_when_ai_report_not_yet_available(self):
        """Regression: a mail case with no AnalyzerReport yet for the
        configured AI analyzer (analysis genuinely still pending, or AI
        never dispatched) used to crash manage_ai_jobs with an
        UnboundLocalError that propagated out of get_report()'s try block —
        skipping collect_signals / score_case / apply_verdict entirely and
        leaving Case.results at its default Inconclusive no matter what the
        other analyzers found. A malicious IP report here must still drive
        the case to Dangerous."""
        user = get_user_model().objects.create_user(username="gr_mail_u", password="x")
        mail = Mail.objects.create(
            subject="s", reportedBy="r", date=timezone.now(), to="t", mail_id="gr-mail-1"
        )
        hash_obj = Hash.objects.create(value="gr-mail-hash")
        archive = File.objects.create(linked_hash=hash_obj, tmp_path="gr-mail.tar.gz")
        MailArchive.objects.create(mail=mail, archive=archive)
        # Deliberately no AnalyzerReport for the AI analyzer.

        ip = IP.objects.create(address="203.0.113.9")
        analyzer = Analyzer.objects.create(name="Abuse2", analyzer_cortex_id="Abuse2", weight=1)
        AnalyzerReport.objects.create(
            cortex_job_id="gr2", type="ip", status="Success", analyzer=analyzer,
            ip=ip, level="malicious", confidence=9, score=9,
            report_summary={"taxonomies": [{"level": "malicious", "value": "abuse"}]},
            report_taxonomy={}, report_full={},
        )
        case = Case.objects.create(description="", reporter=user)
        fm = CaseHasFileOrMail.objects.create(case=case, mail=mail)
        case.fileOrMail = fm
        iocs = CaseHasNonFileIocs.objects.create(case=case, ip=ip)
        case.nonFileIocs = iocs
        case.save()

        CortexAnalyzerReports.get_report(case)

        case.refresh_from_db()
        self.assertEqual(case.results, Result.DANGEROUS)
