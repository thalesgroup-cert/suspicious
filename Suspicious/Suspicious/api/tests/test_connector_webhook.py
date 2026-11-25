"""POST /api/connectors/<name>/webhook/: the generic engine callback; cortex behaves as /api/cortex/webhook/."""
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from case_handler.models import Case
from connectors.base import PROVIDER_KIND_ANALYSIS, Connector, ConnectorManifest, HealthStatus
from connectors.models import ConnectorState
from connectors.registry import ConnectorRegistry
from cortex_job.models import Analyzer, AnalyzerReport, CaseAnalyzerJob
from ip_process.models import IP

URL = "/api/connectors/cortex/webhook/"
DELAY = "tasp.tasks.reconcile_case.delay"


@override_settings(CORTEX_WEBHOOK_SECRET="testsecret")
class CortexOnGenericRouteTest(TestCase):
    def setUp(self):
        patcher = patch("settings.config.get_section", return_value={})
        patcher.start()
        self.addCleanup(patcher.stop)
        cache.clear()
        self.client = APIClient()
        reporter = get_user_model().objects.create_user(username="wh_user", password="x")
        self.case = Case.objects.create(status="On Going", description="", reporter=reporter)
        self.analyzer = Analyzer.objects.create(name="A1", analyzer_cortex_id="c1")
        ar = AnalyzerReport.objects.create(
            cortex_job_id="job-1", type="ip", analyzer=self.analyzer, status="InProgress", level="info",
            confidence=0, score=0, report_summary={}, report_taxonomy={}, report_full={},
            ip=IP.objects.create(address="9.9.9.9"),
        )
        self.caj = CaseAnalyzerJob.objects.create(
            case=self.case, cortex_job_id="job-1", analyzer=self.analyzer, analyzer_report=ar)

    def post(self, payload=None, token="testsecret", url=URL):
        extra = {} if token is None else {"HTTP_AUTHORIZATION": f"Bearer {token}"}
        return self.client.post(url, {"jobId": "job-1"} if payload is None else payload, format="json", **extra)

    @patch(DELAY)
    def test_authenticated_dispatches_per_case(self, delay):
        self.assertEqual(self.post().status_code, 202)
        delay.assert_called_once_with(self.case.id)

    @patch(DELAY)
    def test_wrong_secret_401(self, delay):
        self.assertEqual(self.post(token="wrong").status_code, 401)
        delay.assert_not_called()

    @patch(DELAY)
    def test_missing_header_401(self, delay):
        self.assertEqual(self.post(token=None).status_code, 401)
        delay.assert_not_called()

    @patch(DELAY)
    def test_duplicate_dropped(self, delay):
        self.post()
        self.assertEqual(self.post().status_code, 200)
        self.assertEqual(delay.call_count, 1)

    @patch(DELAY)
    def test_no_pending_row_202(self, delay):
        self.caj.status = CaseAnalyzerJob.STATUS_SUCCESS
        self.caj.save(update_fields=["status"])
        self.assertEqual(self.post().status_code, 202)
        delay.assert_not_called()

    @patch(DELAY)
    def test_missing_job_id_400(self, delay):
        self.assertEqual(self.post({}).status_code, 400)
        delay.assert_not_called()

    @override_settings(CORTEX_WEBHOOK_SECRET="")
    @patch(DELAY)
    def test_unconfigured_503(self, delay):
        resp = self.post()
        self.assertEqual(resp.status_code, 503)
        self.assertEqual(resp.json(), {"detail": "Webhook not configured."})
        delay.assert_not_called()

    def test_runtime_secret_replaces_setting_and_setting_is_fallback(self):
        with patch("settings.config.get_section", return_value={"webhook_secret": "new"}):
            self.assertEqual(self.post({"jobId": "n"}, token="testsecret").status_code, 401)
            self.assertEqual(self.post({"jobId": "n"}, token="new").status_code, 202)
        self.assertEqual(self.post({"jobId": "m"}).status_code, 202)

    def test_delivery_records_last_webhook_time(self):
        self.post()
        self.assertIsNotNone(cache.get("cortex_last_webhook_at"))

    @patch(DELAY)
    def test_accepted_while_disabled(self, delay):
        ConnectorState.objects.update_or_create(name="cortex", defaults={"enabled": False})
        self.assertEqual(self.post().status_code, 202)
        delay.assert_called_once_with(self.case.id)

    def test_dedup_written_only_after_authentication(self):
        self.post(token="wrong")
        self.assertIsNone(cache.get("cortex_job_processed:job-1"))
        self.post()
        self.assertIsNotNone(cache.get("cortex_job_processed:job-1"))

    def test_unreadable_config_falls_back_to_setting(self):
        with patch("connectors.engines.registry.instantiate", side_effect=RuntimeError("boom")), \
                patch(DELAY) as delay:
            self.assertEqual(self.post(token="wrong").status_code, 401)
            self.assertEqual(self.post().status_code, 202)
        delay.assert_called_once_with(self.case.id)

    def test_bad_token_beats_missing_job_id(self):
        for url in (URL, "/api/cortex/webhook/"):
            self.assertEqual(self.post({}, token="wrong", url=url).status_code, 401)

    @override_settings(CORTEX_WEBHOOK_SECRET="")
    def test_unconfigured_beats_bad_token(self):
        for url in (URL, "/api/cortex/webhook/"):
            self.assertEqual(self.post(token="wrong", url=url).status_code, 503)

    def test_unknown_connector_404(self):
        self.assertEqual(self.post(url="/api/connectors/nope/webhook/").status_code, 404)

    def test_non_analysis_connector_404(self):
        self.assertEqual(self.post(url="/api/connectors/thehive/webhook/").status_code, 404)

    def test_old_route_still_works(self):
        with patch(DELAY) as delay:
            self.assertEqual(self.post(url="/api/cortex/webhook/").status_code, 202)
        delay.assert_called_once_with(self.case.id)


class FakeEngine(Connector):
    manifest = ConnectorManifest(name="fake", version="0.0.1", provides=PROVIDER_KIND_ANALYSIS)

    def health_check(self):
        return HealthStatus(ok=True)

    def webhook(self, headers, payload):
        if headers.get("Authorization") != "Bearer fk":
            return None
        return [str(payload["id"])]


class NoWebhookEngine(FakeEngine):
    manifest = ConnectorManifest(name="nohook", version="0.0.1", provides=PROVIDER_KIND_ANALYSIS)

    def webhook(self, headers, payload):
        raise NotImplementedError


class FakeEngineWebhookTest(TestCase):
    def setUp(self):
        cache.clear()
        reg = ConnectorRegistry()
        reg.register(FakeEngine)
        reg.register(NoWebhookEngine)
        patcher = patch("connectors.engines.registry", reg)
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = patch("settings.config.get_section", return_value={})
        patcher.start()
        self.addCleanup(patcher.stop)
        reporter = get_user_model().objects.create_user(username="fk_user", password="x")
        self.mine = Case.objects.create(status="On Going", description="", reporter=reporter)
        self.other = Case.objects.create(status="On Going", description="", reporter=reporter)
        an = Analyzer.objects.create(name="FK", analyzer_cortex_id="fake:a", source="fake")
        CaseAnalyzerJob.objects.create(case=self.mine, cortex_job_id="fake-x1", analyzer=an)
        CaseAnalyzerJob.objects.create(case=self.other, cortex_job_id="x1", analyzer=an)  # a cortex-style raw id

    @patch(DELAY)
    def test_reaches_reconcile_for_own_rows_only(self, delay):
        resp = APIClient().post("/api/connectors/fake/webhook/", {"id": "x1"}, format="json",
                                HTTP_AUTHORIZATION="Bearer fk")
        self.assertEqual(resp.status_code, 202)
        delay.assert_called_once_with(self.mine.id)
        self.assertIsNotNone(cache.get("fake_job_processed:x1"))

    @patch(DELAY)
    def test_wrong_secret_401(self, delay):
        resp = APIClient().post("/api/connectors/fake/webhook/", {"id": "x1"}, format="json")
        self.assertEqual(resp.status_code, 401)
        delay.assert_not_called()

    def test_not_implemented_404(self):
        resp = APIClient().post("/api/connectors/nohook/webhook/", {}, format="json")
        self.assertEqual(resp.status_code, 404)
