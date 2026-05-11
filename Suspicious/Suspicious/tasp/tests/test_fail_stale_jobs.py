from datetime import timedelta
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from case_handler.models import Case
from cortex_job.models import Analyzer, CaseAnalyzerJob
from tasp.tasks import fail_stale_jobs


class FailStaleJobsTest(TestCase):
    def setUp(self):
        User = get_user_model()
        self.reporter = User.objects.create_user(
            username="stale_jobs_user", password="x"
        )
        self.case = Case.objects.create(
            status="On Going", description="", reporter=self.reporter
        )
        self.analyzer = Analyzer.objects.create(
            name="A1", analyzer_cortex_id="c1"
        )

    def test_old_pending_caj_marked_failure(self):
        old_caj = CaseAnalyzerJob.objects.create(
            case=self.case,
            cortex_job_id="j-old",
            analyzer=self.analyzer,
            status=CaseAnalyzerJob.STATUS_INPROGRESS,
        )
        # Force created_at into the past (auto_now_add prevents direct assignment)
        CaseAnalyzerJob.objects.filter(pk=old_caj.pk).update(
            created_at=timezone.now() - timedelta(days=2),
        )
        fail_stale_jobs.apply().get()
        old_caj.refresh_from_db()
        self.assertEqual(old_caj.status, CaseAnalyzerJob.STATUS_FAILURE)
        self.assertIsNotNone(old_caj.completed_at)

    def test_recent_pending_caj_untouched(self):
        new_caj = CaseAnalyzerJob.objects.create(
            case=self.case,
            cortex_job_id="j-new",
            analyzer=self.analyzer,
            status=CaseAnalyzerJob.STATUS_INPROGRESS,
        )
        fail_stale_jobs.apply().get()
        new_caj.refresh_from_db()
        self.assertEqual(new_caj.status, CaseAnalyzerJob.STATUS_INPROGRESS)
        self.assertIsNone(new_caj.completed_at)
