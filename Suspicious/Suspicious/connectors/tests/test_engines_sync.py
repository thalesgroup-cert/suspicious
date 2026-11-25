"""engines.sync_catalog: the analyzer catalogue sync, for any analysis engine."""
from unittest import mock

import requests
from cortex4py.exceptions import AuthenticationError
from django.test import TestCase

from connectors import engines
from connectors.base import CatalogEntry
from connectors.contrib.cortex.connector import CortexConnector
from connectors.registry import ConnectorRegistry
from connectors.tests.test_engines_dispatch import make_engine
from cortex_job.models import Analyzer
from tasp.cron.sync_cortex import sync_cortex_analyzers

ROLES = {"header": "Hdr", "ai": "AI", "yara": None, "sandbox": None, "file_info": None}


def entry(name, id_="i"):
    return CatalogEntry(id=id_ + name, name=name, data_types=("url",))


class SyncCatalogTest(TestCase):
    def setUp(self):
        self.fake = make_engine("fake")
        self.fake.offered = []
        self.fake.catalog = lambda connector, data_type=None, name=None: list(type(connector).offered)
        self.registry = ConnectorRegistry()
        for cls in (self.fake, CortexConnector):
            self.registry.register(cls)
        patcher = mock.patch("connectors.engines.registry", self.registry)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_fake_engine_rows_get_source_and_namespaced_ids(self):
        self.fake.offered = [entry("A1")]
        self.assertEqual(engines.sync_catalog("fake"), 1)
        row = Analyzer.objects.get(name="A1")
        self.assertEqual((row.source, row.analyzer_cortex_id, row.is_active), ("fake", "fake:iA1", True))

    def test_absent_names_deactivate_only_that_source(self):
        Analyzer.objects.create(name="old", analyzer_cortex_id="fake:o", source="fake")
        Analyzer.objects.create(name="cx", analyzer_cortex_id="c", source="cortex")
        self.fake.offered = [entry("A1")]
        engines.sync_catalog("fake")
        self.assertFalse(Analyzer.objects.get(name="old").is_active)
        self.assertTrue(Analyzer.objects.get(name="cx").is_active)

    def test_a_name_owned_by_cortex_is_skipped_and_not_counted(self):
        Analyzer.objects.create(name="Dup", analyzer_cortex_id="c", source="cortex")
        self.fake.offered = [entry("Dup"), entry("A1")]
        with self.assertLogs("tasp.cron.fetch_analyzer", level="ERROR"):
            self.assertEqual(engines.sync_catalog("fake"), 1)
        self.assertEqual(Analyzer.objects.get(name="Dup").source, "cortex")

    def test_an_empty_catalogue_changes_nothing(self):
        Analyzer.objects.create(name="old", analyzer_cortex_id="fake:o", source="fake")
        self.assertEqual(engines.sync_catalog("fake"), 0)
        self.assertTrue(Analyzer.objects.get(name="old").is_active)

    def test_unfiltered_cortex_catalog_raises_on_connection_error(self):
        connector = CortexConnector({"url": "http://cortex:9001", "api_key": "k"})
        with mock.patch("cortex_job.cortex_utils.session_cortex_api.SessionCortexApi.do_get",
                        side_effect=requests.ConnectionError("down")):
            with self.assertRaises(requests.ConnectionError):
                connector.catalog()

    def test_authentication_error_is_not_retryable(self):
        connector = CortexConnector({"url": "http://cortex:9001", "api_key": "k"})
        with mock.patch("cortex_job.cortex_utils.session_cortex_api.SessionCortexApi.do_get",
                        side_effect=AuthenticationError("401")):
            with self.assertRaises(AuthenticationError) as ctx:
                connector.catalog()
        self.assertIs(ctx.exception.retryable, False)

    def test_configured_roles_check_still_logs_an_error(self):
        self.fake.offered = [entry("Other")]
        cortex = [entry("Cx")]
        with mock.patch("settings.config.get_section", return_value={"analyzers": ROLES}), \
                mock.patch.object(CortexConnector, "catalog", return_value=cortex):
            with self.assertLogs("tasp.cron.fetch_analyzer", level="ERROR") as cm:
                engines.sync_catalog("cortex")
        self.assertTrue(any("header" in m and "'Hdr'" in m for m in cm.output))

    def test_sync_cortex_analyzers_strict_reraises_and_default_swallows(self):
        cfg = mock.Mock()
        cfg.cortex.url, cfg.cortex.api_key = "http://cortex:9001/", "k"
        with mock.patch("tasp.cron.sync_cortex.load_config", return_value=cfg), \
                mock.patch("tasp.cron.sync_cortex._fetch_all_analyzers",
                           side_effect=requests.ConnectionError("down")):
            self.assertIsNone(sync_cortex_analyzers())
            with self.assertRaises(requests.ConnectionError):
                sync_cortex_analyzers(strict=True)
