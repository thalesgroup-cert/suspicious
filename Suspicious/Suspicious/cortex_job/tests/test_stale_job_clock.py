from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from case_handler.models import Case
from cortex_job.models import Analyzer, AnalyzerReport, CaseAnalyzerJob


class StaleJobClockTest(TestCase):
    """R6 regression: the inline stale-rescue in get_cortex_jobs_results
    must compute age from CaseAnalyzerJob.created_at (job submission
    time), not from AnalyzerReport.creation_date which can be rewritten
    after a Deleted/resurrected cycle and so undercount queue lag.
    """

    def setUp(self):
        User = get_user_model()
        self.reporter = User.objects.create_user(username="r6", password="x")
        self.case = Case.objects.create(
            description="", reporter=self.reporter, results="Safe",
        )
        self.analyzer = Analyzer.objects.create(
            name="a", analyzer_cortex_id="aid", weight=1.0,
        )

    def _make_report_and_caj(self, job_id: str, caj_created_at, report_created_at):
        report = AnalyzerReport.objects.create(
            cortex_job_id=job_id, type="file", status="Waiting",
            analyzer=self.analyzer, level="info",
            confidence=0, score=0,
            report_summary={}, report_taxonomy={}, report_full={},
        )
        # auto_now_add fields need explicit update to backdate
        AnalyzerReport.objects.filter(pk=report.pk).update(
            creation_date=report_created_at
        )
        caj = CaseAnalyzerJob.objects.create(
            case=self.case, cortex_job_id=job_id,
            analyzer=self.analyzer, analyzer_report=report,
            status=CaseAnalyzerJob.STATUS_WAITING,
        )
        CaseAnalyzerJob.objects.filter(pk=caj.pk).update(
            created_at=caj_created_at
        )
        report.refresh_from_db()
        return report

    def test_stale_clock_uses_caj_created_at_not_report_creation(self):
        """Older CAJ.created_at should trigger stale-fail even when the
        report's creation_date is recent (e.g. after a Deleted/resurrect
        cycle that re-stamped creation_date)."""
        from cortex_job.cortex_utils.cortex_and_job_management import (
            CortexJobManager,
            STALE_JOB_TIMEOUT_SECONDS,
        )

        now = timezone.now()
        # CAJ submitted well past the stale threshold
        caj_created = now - timedelta(seconds=STALE_JOB_TIMEOUT_SECONDS + 60)
        # Report row rewritten recently — by itself this is NOT stale
        report_created = now - timedelta(seconds=10)

        report = self._make_report_and_caj("job-r6", caj_created, report_created)

        with patch.object(CortexJobManager, "get_job_from_api", return_value=None):
            status = CortexJobManager.get_cortex_jobs_results(report, "file")

        report.refresh_from_db()
        self.assertEqual(status, "Failure")
        self.assertEqual(report.status, "Failure")

    def test_recent_caj_keeps_report_pending(self):
        """When CAJ.created_at is recent, the report stays pending even
        if AnalyzerReport.creation_date is artificially old."""
        from cortex_job.cortex_utils.cortex_and_job_management import (
            CortexJobManager,
            STALE_JOB_TIMEOUT_SECONDS,
        )

        now = timezone.now()
        caj_created = now - timedelta(seconds=10)
        # Report row creation_date stamped older than the threshold
        report_created = now - timedelta(seconds=STALE_JOB_TIMEOUT_SECONDS + 60)

        report = self._make_report_and_caj("job-r6b", caj_created, report_created)

        with patch.object(CortexJobManager, "get_job_from_api", return_value=None):
            status = CortexJobManager.get_cortex_jobs_results(report, "file")

        report.refresh_from_db()
        self.assertEqual(status, "Waiting")
        self.assertEqual(report.status, "Waiting")
