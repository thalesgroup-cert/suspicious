from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from case_handler.models import Case
from cortex_job.models import Analyzer, AnalyzerReport, CaseAnalyzerJob


@override_settings(CORTEX_WEBHOOK_SECRET="testsecret")
class CortexWebhookTest(TestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()
        User = get_user_model()
        self.reporter = User.objects.create_user(
            username="webhook_test_user", password="x"
        )
        self.case = Case.objects.create(
            status="On Going", description="", reporter=self.reporter
        )
        self.analyzer = Analyzer.objects.create(
            name="A1", analyzer_cortex_id="c1"
        )
        self.ar = AnalyzerReport.objects.create(
            cortex_job_id="job-1",
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
        self.caj = CaseAnalyzerJob.objects.create(
            case=self.case,
            cortex_job_id="job-1",
            analyzer=self.analyzer,
            analyzer_report=self.ar,
        )

    @patch("tasp.tasks.process_cortex_job.delay")
    def test_authenticated_webhook_dispatches_per_case(self, mock_delay):
        resp = self.client.post(
            "/api/cortex/webhook/",
            {"jobId": "job-1"},
            HTTP_AUTHORIZATION="Bearer testsecret",
            format="json",
        )
        self.assertEqual(resp.status_code, 202)
        mock_delay.assert_called_once_with(self.case.id, "job-1")

    @patch("tasp.tasks.process_cortex_job.delay")
    def test_unauth_returns_401(self, mock_delay):
        resp = self.client.post(
            "/api/cortex/webhook/",
            {"jobId": "job-1"},
            HTTP_AUTHORIZATION="Bearer wrong",
            format="json",
        )
        self.assertEqual(resp.status_code, 401)
        mock_delay.assert_not_called()

    @patch("tasp.tasks.process_cortex_job.delay")
    def test_dedup_drops_duplicate_jobid(self, mock_delay):
        for _ in range(2):
            self.client.post(
                "/api/cortex/webhook/",
                {"jobId": "job-1"},
                HTTP_AUTHORIZATION="Bearer testsecret",
                format="json",
            )
        self.assertEqual(mock_delay.call_count, 1)

    @patch("tasp.tasks.process_cortex_job.delay")
    def test_no_pending_caj_skips_dispatch(self, mock_delay):
        self.caj.status = CaseAnalyzerJob.STATUS_SUCCESS
        self.caj.save(update_fields=["status"])
        resp = self.client.post(
            "/api/cortex/webhook/",
            {"jobId": "job-1"},
            HTTP_AUTHORIZATION="Bearer testsecret",
            format="json",
        )
        self.assertEqual(resp.status_code, 202)
        mock_delay.assert_not_called()
