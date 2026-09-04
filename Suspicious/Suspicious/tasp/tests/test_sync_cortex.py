"""sync_cortex_analyzers previously used cortex4py's find_all(), which POSTs
/api/analyzer/_search — an endpoint Cortex 4.1.0 (the version this project
targets) no longer serves, so the periodic sync silently updated zero rows,
every tick, forever. It also constructed the Cortex client from a pydantic
HttpUrl that renders with a trailing slash, doubling the "/api/" cortex4py
appends. Neither failure raised past sync_cortex_analyzers' own broad
except blocks, so nothing ever surfaced it."""
from unittest.mock import MagicMock, patch

from django.test import TestCase

from cortex_job.models import Analyzer
from tasp.cron.models import CortexConfig, CronConfig, MinioConfig
from tasp.cron.sync_cortex import sync_cortex_analyzers


def _fake_cron_config(url="http://cortex:9001/"):
    return CronConfig(
        s3=MinioConfig(endpoint="rustfs:9000", access_key="a", secret_key="b"),
        cortex=CortexConfig(url=url, api_key="k"),
    )


class SyncCortexAnalyzersTests(TestCase):
    def _run_with_fake_analyzers(self, payload, url="http://cortex:9001/"):
        response = MagicMock()
        response.json.return_value = payload
        with patch(
            "tasp.cron.sync_cortex.load_config", return_value=_fake_cron_config(url),
        ), patch(
            "cortex_job.cortex_utils.session_cortex_api.SessionCortexApi.do_get",
            return_value=response,
        ) as mock_do_get:
            sync_cortex_analyzers()
        return mock_do_get

    def test_uses_get_not_the_broken_search_post(self):
        mock_do_get = self._run_with_fake_analyzers([])
        mock_do_get.assert_called_once_with("analyzer", params={"range": "all"})

    def test_upserts_analyzer_rows_from_response(self):
        self._run_with_fake_analyzers(
            [{"id": "abc123", "name": "DShield_lookup_1_0"}]
        )
        row = Analyzer.objects.get(name="DShield_lookup_1_0")
        self.assertEqual(row.analyzer_cortex_id, "abc123")
        self.assertTrue(row.is_active)

    def test_analyzers_no_longer_enabled_are_marked_inactive(self):
        Analyzer.objects.create(
            name="Removed_Analyzer_1_0", analyzer_cortex_id="old-id",
            weight=0.2, is_active=True,
        )
        self._run_with_fake_analyzers([{"id": "new-id", "name": "Still_Here_1_0"}])
        stale = Analyzer.objects.get(name="Removed_Analyzer_1_0")
        self.assertFalse(stale.is_active)

    def test_trailing_slash_in_configured_url_is_stripped(self):
        with patch(
            "tasp.cron.sync_cortex.load_config",
            return_value=_fake_cron_config("http://cortex:9001/"),
        ), patch(
            "tasp.cron.sync_cortex.SessionCortexApi"
        ) as MockSessionApi:
            MockSessionApi.return_value.do_get.return_value.json.return_value = []
            sync_cortex_analyzers()
            (base_url, _api_key), _kwargs = MockSessionApi.call_args
            self.assertFalse(base_url.endswith("/"))
            self.assertEqual(base_url, "http://cortex:9001")
