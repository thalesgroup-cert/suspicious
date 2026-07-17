"""Starter tests — none of this needs Django or a running Suspicious
instance, since ConnectorManifest.validate() and health_check() are both
plain Python. Hooks that touch the database (Case.objects...) need the
Suspicious test harness instead; keep hook bodies thin and delegate to a
plain-Python service class you can unit test on its own, the way
connectors/contrib/misp does with MISPService.
"""
from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from suspicious_connector_template.connector import TemplateConnector


class ManifestTest(unittest.TestCase):
    def test_manifest_is_valid(self):
        TemplateConnector.manifest.validate()


class HealthCheckTest(unittest.TestCase):
    def test_unconfigured_is_not_ok(self):
        connector = TemplateConnector(config={})
        status = connector.health_check()
        self.assertFalse(status.ok)

    @patch("suspicious_connector_template.connector.requests.get")
    def test_reachable_is_ok(self, mock_get):
        mock_get.return_value = MagicMock(raise_for_status=lambda: None)
        connector = TemplateConnector(config={
            "api_url": "https://example.com",
            "api_token": "token",
        })
        status = connector.health_check()
        self.assertTrue(status.ok)

    @patch("suspicious_connector_template.connector.requests.get")
    def test_request_failure_is_not_ok_not_raised(self, mock_get):
        mock_get.side_effect = ConnectionError("refused")
        connector = TemplateConnector(config={
            "api_url": "https://example.com",
            "api_token": "token",
        })
        status = connector.health_check()
        self.assertFalse(status.ok)
        self.assertIn("refused", status.detail)


if __name__ == "__main__":
    unittest.main()
