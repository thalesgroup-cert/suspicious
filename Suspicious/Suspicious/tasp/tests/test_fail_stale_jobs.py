from unittest import mock
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


class FailStaleJobsPerEngineTimeoutTest(TestCase):
    """Each row waits for its own engine's stale_job_timeout_seconds (7200 when absent)."""

    def setUp(self):
        from connectors.base import Connector, ConnectorManifest, PROVIDER_KIND_ANALYSIS
        from connectors.registry import ConnectorRegistry

        reg = ConnectorRegistry()
        for name in ("eng_fast", "eng_slow"):
            reg.register(type(name, (Connector,), {"manifest": ConnectorManifest(
                name=name, version="0.0.1", description="fixture", provides=PROVIDER_KIND_ANALYSIS)}))
        patcher = mock.patch("connectors.engines.registry", reg)
        patcher.start()
        self.addCleanup(patcher.stop)
        sections = {
            "integrations.eng_fast": {"stale_job_timeout_seconds": 600},
            "integrations.eng_slow": {"stale_job_timeout_seconds": 86400},
        }
        patcher = mock.patch("settings.config.get_section", side_effect=lambda n: dict(sections.get(n, {})))
        patcher.start()
        self.addCleanup(patcher.stop)
        reporter = get_user_model().objects.create_user(username="stale_engines", password="x")
        self.case = Case.objects.create(status="On Going", description="", reporter=reporter)

    def _row(self, source, age):
        analyzer = Analyzer.objects.create(name=f"A_{source}", analyzer_cortex_id=f"{source}:a", source=source)
        caj = CaseAnalyzerJob.objects.create(
            case=self.case, cortex_job_id=f"{source}-j", analyzer=analyzer,
            status=CaseAnalyzerJob.STATUS_INPROGRESS,
        )
        CaseAnalyzerJob.objects.filter(pk=caj.pk).update(created_at=timezone.now() - age)
        return caj

    def _status(self, caj):
        caj.refresh_from_db()
        return caj.status

    def test_only_the_row_older_than_its_own_engine_timeout_fails(self):
        fast = self._row("eng_fast", timedelta(hours=1))   # past 600 s
        slow = self._row("eng_slow", timedelta(hours=3))   # under 86400 s, past the 7200 default
        fail_stale_jobs.apply().get()
        self.assertEqual(self._status(fast), CaseAnalyzerJob.STATUS_FAILURE)
        self.assertEqual(self._status(slow), CaseAnalyzerJob.STATUS_INPROGRESS)

    def test_an_unregistered_source_uses_7200(self):
        old = self._row("gone_engine", timedelta(hours=3))
        young = self._row("gone_too", timedelta(hours=1))
        fail_stale_jobs.apply().get()
        self.assertEqual(self._status(old), CaseAnalyzerJob.STATUS_FAILURE)
        self.assertEqual(self._status(young), CaseAnalyzerJob.STATUS_INPROGRESS)
