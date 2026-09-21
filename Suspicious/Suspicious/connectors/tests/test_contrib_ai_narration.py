from unittest import mock

from django.test import SimpleTestCase

from connectors.contrib.ai_narration.connector import AiNarrationConnector
from connectors.registry import registry


class AiNarrationManifestTest(SimpleTestCase):
    def test_manifest_valid_and_not_enabled_by_default(self):
        m = AiNarrationConnector.manifest
        m.validate()
        self.assertFalse(m.enabled_by_default)
        self.assertEqual(m.events, ())

    def test_registered_as_a_builtin(self):
        registry.discover()
        self.assertIn("ai_narration", registry.names())


class AiNarrationHealthCheckTest(SimpleTestCase):
    def test_external_provider_configured_reports_ok(self):
        connector = AiNarrationConnector({"openai_api_key": "sk-x"})
        status = connector.health_check()
        self.assertTrue(status.ok)
        self.assertIn("openai", status.detail)

    @mock.patch("connectors.contrib.ai_narration.connector.requests.get")
    def test_ollama_fallback_reachable_reports_ok(self, mock_get):
        mock_get.return_value = mock.Mock()
        mock_get.return_value.raise_for_status = lambda: None
        connector = AiNarrationConnector({})
        status = connector.health_check()
        self.assertTrue(status.ok)
        self.assertIn("ollama", status.detail)

    @mock.patch("connectors.contrib.ai_narration.connector.requests.get")
    def test_ollama_fallback_unreachable_reports_not_ok(self, mock_get):
        mock_get.side_effect = ConnectionError("refused")
        connector = AiNarrationConnector({})
        status = connector.health_check()
        self.assertFalse(status.ok)
        self.assertIn("ollama", status.detail)
