from unittest import mock

from django.test import TestCase

from connectors.contrib.cortex.connector import CortexConnector
from connectors.delivery import get_state
from connectors.registry import registry

CONFIGURED = {"url": "http://cortex:9001", "api_key": "k"}


class CortexManifestTest(TestCase):
    def test_manifest(self):
        m = CortexConnector.manifest
        m.validate()
        self.assertEqual(m.name, "cortex")
        self.assertEqual(m.provides, "analysis")
        self.assertEqual(m.category, "Analysis")
        self.assertTrue(m.enabled_by_default)
        [schedule] = m.schedules
        self.assertEqual((schedule.name, schedule.interval_seconds), ("sync", 60))
        fields = {f.key: f for f in m.config_schema}
        self.assertEqual(set(fields), {
            "url", "api_key", "webhook_secret", "stale_job_timeout_seconds",
            "analyzers.yara", "analyzers.sandbox", "analyzers.header",
            "analyzers.file_info", "analyzers.ai",
        })
        self.assertEqual(fields["api_key"].type, "secret")
        self.assertEqual(fields["webhook_secret"].type, "secret")
        self.assertEqual(fields["stale_job_timeout_seconds"].default, 7200)
        self.assertTrue(fields["url"].required and fields["api_key"].required)

    def _listing(self, names, status=200):
        return mock.Mock(status_code=status, ok=status < 400, json=lambda: [{"name": n} for n in names])

    def test_health_ok_lists_analyzers_with_the_key(self):
        cfg = {**CONFIGURED, "analyzers": {"yara": "Y", "ai": "not-in-cortex"}}
        with mock.patch("requests.get", return_value=self._listing(["Y", "Z"])) as get:
            status = CortexConnector(cfg).health_check()
        self.assertTrue(status.ok, status.detail)
        self.assertIn("2 analyzers offered", status.detail)
        self.assertEqual(get.call_args.args[0], "http://cortex:9001/api/analyzer")
        self.assertEqual(get.call_args.kwargs["headers"], {"Authorization": "Bearer k"})
        self.assertEqual(get.call_args.kwargs["timeout"], 2)

    def test_health_not_ok_when_the_key_is_rejected(self):
        with mock.patch("requests.get", return_value=self._listing([], status=401)):
            status = CortexConnector(CONFIGURED).health_check()
        self.assertFalse(status.ok)
        self.assertIn("api key rejected", status.detail)

    def test_health_other_http_errors_are_not_read_as_an_empty_catalogue(self):
        cfg = {**CONFIGURED, "analyzers": {"yara": "Y"}}
        for code in (404, 429, 503):
            with mock.patch("requests.get", return_value=self._listing([], status=code)):
                status = CortexConnector(cfg).health_check()
            self.assertEqual((status.ok, status.detail), (False, f"HTTP {code}"))

    def test_health_names_roles_cortex_does_not_offer(self):
        cfg = {**CONFIGURED, "analyzers": {"yara": "Gone", "header": "H"}}
        with mock.patch("requests.get", return_value=self._listing(["H"])):
            status = CortexConnector(cfg).health_check()
        self.assertFalse(status.ok)
        self.assertIn("yara=Gone", status.detail)
        self.assertNotIn("header=H", status.detail)

    def test_health_reports_stuck_jobs_and_webhook_age(self):
        from datetime import timedelta
        from django.core.cache import cache
        from django.utils import timezone
        from cortex_job.models import Analyzer, CaseAnalyzerJob
        from django.contrib.auth import get_user_model
        from case_handler.models import Case

        analyzer = Analyzer.objects.create(name="A1", analyzer_cortex_id="c1")
        case = Case.objects.create(
            status="On Going", description="",
            reporter=get_user_model().objects.create_user(username="r", password="x"),
        )
        job = CaseAnalyzerJob.objects.create(case=case, cortex_job_id="j1", analyzer=analyzer)
        CaseAnalyzerJob.objects.filter(pk=job.pk).update(created_at=timezone.now() - timedelta(hours=1))
        cache.set("cortex_last_webhook_at", __import__("time").time() - 300)
        with mock.patch("requests.get", return_value=self._listing(["A1"])):
            status = CortexConnector(CONFIGURED).health_check()
        self.assertIn("1 jobs pending over 30 min", status.detail)
        self.assertIn("last webhook 5 min ago", status.detail)
        cache.delete("cortex_last_webhook_at")
    def test_health_not_ok_on_connection_error(self):
        with mock.patch("requests.get", side_effect=OSError("down")):
            self.assertFalse(CortexConnector(CONFIGURED).health_check().ok)

    def test_health_unconfigured_returns_not_ok_without_raising(self):
        for cfg in ({}, {"url": "https://cortex.example.com", "api_key": "k"},
                    {"url": "http://cortex:9001", "api_key": ""}):
            with mock.patch("requests.get") as get:
                status = CortexConnector(cfg).health_check()
            self.assertFalse(status.ok)
            get.assert_not_called()
        self.assertIn("api_key", CortexConnector({"url": "http://c"}).health_check().detail)

    def test_sync_calls_sync_cortex_analyzers(self):
        with mock.patch("tasp.cron.sync_cortex.sync_cortex_analyzers") as run:
            CortexConnector(CONFIGURED).sync()
        run.assert_called_once_with(strict=True)

    def test_sync_failure_reaches_the_delivery_ledger(self):
        from connectors.delivery import RetryableDeliveryError, run_sync_now
        from connectors.models import ConnectorDelivery
        import requests

        registry.discover()
        with mock.patch("settings.config.get_section", return_value=CONFIGURED), \
                mock.patch("tasp.cron.sync_cortex._fetch_all_analyzers",
                           side_effect=requests.ConnectionError("down")), \
                mock.patch("tasp.cron.sync_cortex.load_config") as load:
            load.return_value.cortex.url = "http://cortex:9001"
            load.return_value.cortex.api_key = "k"
            with self.assertRaises(RetryableDeliveryError):  # the task retries the sync
                run_sync_now("cortex")
        self.assertEqual(ConnectorDelivery.objects.get(connector="cortex").status, "failed")

    def test_a_60s_sync_logs_one_success_an_hour_and_every_failure(self):
        from datetime import timedelta
        from django.utils import timezone
        from connectors.delivery import RetryableDeliveryError, run_sync_now
        from connectors.models import ConnectorDelivery

        registry.discover()
        rows = lambda: ConnectorDelivery.objects.filter(connector="cortex", event="sync")
        with mock.patch.object(CortexConnector, "sync"):
            run_sync_now("cortex")
            run_sync_now("cortex")
            self.assertEqual(rows().count(), 1)  # the second success is not logged
            rows().update(created_at=timezone.now() - timedelta(hours=2))
            run_sync_now("cortex")
            self.assertEqual(rows().count(), 2)  # an hour on, one more
        with mock.patch.object(CortexConnector, "sync", side_effect=OSError("down")):
            with self.assertRaises(RetryableDeliveryError):
                run_sync_now("cortex")
        with mock.patch.object(CortexConnector, "sync"):
            run_sync_now("cortex")
        self.assertEqual(list(rows().order_by("id").values_list("status", flat=True)),
                         ["success", "success", "failed", "success"])  # recovery is logged at once

    def test_the_connector_sync_does_not_count_the_shared_breaker_twice(self):
        from tasp.cron import sync_cortex
        remote = mock.Mock(name="a", id="1")
        remote.name = "A1"
        with mock.patch.object(sync_cortex, "load_config") as load, \
                mock.patch.object(sync_cortex, "_fetch_all_analyzers", return_value=[remote]) as fetch:
            load.return_value.cortex.url = "http://cortex:9001"
            load.return_value.cortex.api_key = "k"
            sync_cortex.sync_cortex_analyzers(strict=True)
            self.assertIs(fetch.call_args.kwargs["guarded"], False)
            sync_cortex.sync_cortex_analyzers()
            self.assertIs(fetch.call_args.kwargs["guarded"], True)

    def test_sync_when_unconfigured_does_nothing(self):
        with mock.patch("tasp.cron.sync_cortex.sync_cortex_analyzers") as run:
            CortexConnector({}).sync()
        run.assert_not_called()


class CortexRegistrationTest(TestCase):
    def test_registered_and_enabled_on_a_fresh_database(self):
        registry.discover()
        self.assertIn("cortex", registry.names())
        self.assertTrue(get_state("cortex").enabled)

    def test_beat_has_one_cortex_sync_entry(self):
        from django.conf import settings
        from suspicious.celery import app
        from connectors.apps import ConnectorsConfig

        self.assertNotIn("sync-cortex", settings.CELERY_BEAT_SCHEDULE)
        registry.discover()
        ConnectorsConfig._register_beat_schedules()
        entry = app.conf.beat_schedule["connector-cortex-sync"]
        self.assertEqual(entry["args"], ["cortex"])
        self.assertEqual(entry["schedule"], 60.0)
        self.assertNotIn("sync-cortex", app.conf.beat_schedule)

    def test_sync_cortex_task_runs_the_connector_sync(self):
        from tasp.tasks import sync_cortex
        with mock.patch("connectors.delivery.run_sync_now") as run:
            sync_cortex.apply()
        run.assert_called_once_with("cortex")


# integrations.cortex exactly as in docs/getting-started/examples/Suspicious-settings.example.json,
# with a key filled in: an existing deployment's section must work with no edit.
EXISTING_SECTION = {
    "url": "http://cortex:9001",
    "api_key": "k",
    "analyzers": {
        "header": "Mail_Header_Analyzer_1_0",
        "ai": "AI_Mail_Analyzer",
        "sandbox": "ThreatGridOnPrem_1_0",
        "yara": "Yara_Boosted_3_2",
        "file_info": "FileInfo_8_0",
    },
    "webhook_secret": "",
}


class UpgradeTests(TestCase):
    def setUp(self):
        registry.discover()
        for target in ("settings.config.get_section", "api.views.connectors.get_section"):
            patcher = mock.patch(
                target, side_effect=lambda n: EXISTING_SECTION if n == "integrations.cortex" else {},
            )
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_existing_section_reaches_the_connector(self):
        config = registry.instantiate("cortex").config
        self.assertEqual(config["url"], "http://cortex:9001")
        self.assertEqual(config["api_key"], "k")
        self.assertEqual(
            set(config["analyzers"]), {"header", "ai", "sandbox", "yara", "file_info"},
        )

    def test_reads_as_connected_with_no_state_row(self):
        from api.views.connectors import _serialize_connector
        self.assertEqual(_serialize_connector("cortex")["status"], "connected")

    def test_listed_and_enabled_over_the_api(self):
        from django.contrib.auth import get_user_model
        from django.contrib.auth.models import Group
        from rest_framework.test import APIClient

        user = get_user_model().objects.create_user(username="admin", password="x")
        user.groups.add(Group.objects.get_or_create(name="Admin")[0])
        client = APIClient()
        client.force_authenticate(user)
        items = client.get("/api/connectors/").json()["connectors"]
        [cortex] = [c for c in items if c["name"] == "cortex"]
        self.assertTrue(cortex["enabled"])
