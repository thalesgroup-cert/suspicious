import pytest
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

    def test_pending_statuses_constant(self):
        self.assertEqual(
            CaseAnalyzerJob.PENDING_STATUSES,
            (CaseAnalyzerJob.STATUS_WAITING, CaseAnalyzerJob.STATUS_INPROGRESS),
        )
