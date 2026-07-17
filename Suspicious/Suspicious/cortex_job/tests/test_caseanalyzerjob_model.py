from django.contrib.auth import get_user_model
from django.db import IntegrityError
from django.test import TestCase
from cortex_job.models import Analyzer, CaseAnalyzerJob
from case_handler.models import Case


class CaseAnalyzerJobConstraintsTest(TestCase):
    def setUp(self):
        User = get_user_model()
        self.reporter = User.objects.create_user(
            username="test_reporter", password="x"
        )
        self.analyzer = Analyzer.objects.create(
            name="A1", analyzer_cortex_id="c1"
        )
        self.case = Case.objects.create(
            status="On Going",
            description="",
            reporter=self.reporter,
        )

    def test_unique_case_cortexjob(self):
        CaseAnalyzerJob.objects.create(
            case=self.case,
            cortex_job_id="job-1",
            analyzer=self.analyzer,
        )
        with self.assertRaises(IntegrityError):
            CaseAnalyzerJob.objects.create(
                case=self.case,
                cortex_job_id="job-1",
                analyzer=self.analyzer,
            )

    def test_default_status_is_inprogress(self):
        caj = CaseAnalyzerJob.objects.create(
            case=self.case,
            cortex_job_id="job-2",
            analyzer=self.analyzer,
        )
        self.assertEqual(caj.status, CaseAnalyzerJob.STATUS_INPROGRESS)

    def test_case_delete_cascades_caj(self):
        """Deleting a Case removes its CAJ rows (CASCADE)."""
        caj = CaseAnalyzerJob.objects.create(
            case=self.case,
            cortex_job_id="job-cascade",
            analyzer=self.analyzer,
        )
        self.case.delete()
        self.assertFalse(CaseAnalyzerJob.objects.filter(pk=caj.pk).exists())

    def test_analyzer_delete_protects_caj(self):
        """Deleting an Analyzer with active CAJ rows raises ProtectedError (PROTECT)."""
        from django.db.models.deletion import ProtectedError
        CaseAnalyzerJob.objects.create(
            case=self.case,
            cortex_job_id="job-protect",
            analyzer=self.analyzer,
        )
        with self.assertRaises(ProtectedError):
            self.analyzer.delete()

    def test_analyzer_report_delete_sets_null(self):
        """Deleting an AnalyzerReport leaves the CAJ row but NULLs the FK (SET_NULL)."""
        from cortex_job.models import AnalyzerReport
        ar = AnalyzerReport.objects.create(
            cortex_job_id="job-setnull",
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
        caj = CaseAnalyzerJob.objects.create(
            case=self.case,
            cortex_job_id="job-setnull",
            analyzer=self.analyzer,
            analyzer_report=ar,
        )
        ar.delete()
        caj.refresh_from_db()
        self.assertIsNone(caj.analyzer_report)
