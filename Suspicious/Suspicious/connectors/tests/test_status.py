from unittest.mock import patch

from django.test import SimpleTestCase

from api.views.connectors import _compute_status
from connectors.base import ConfigField


class ComputeStatusTest(SimpleTestCase):
    def setUp(self):
        self.schema = (
            ConfigField("url", "url", required=True),
            ConfigField("api_key", "secret", required=True),
            ConfigField("timeout", "int", required=False),
        )

    def test_disabled_when_not_enabled(self):
        self.assertEqual(
            _compute_status("x", self.schema, enabled=False, section={"url": "x"}),
            "disabled",
        )

    @patch("api.views.connectors.get_secret", return_value="")
    def test_partial_when_required_secret_missing(self, mock_secret):
        self.assertEqual(
            _compute_status("x", self.schema, enabled=True, section={"url": "x"}),
            "partial",
        )

    @patch("api.views.connectors.get_secret", return_value="s3cr3t")
    def test_connected_when_all_required_filled(self, mock_secret):
        self.assertEqual(
            _compute_status("x", self.schema, enabled=True, section={"url": "x"}),
            "connected",
        )

    def test_connected_when_no_required_fields(self):
        self.assertEqual(
            _compute_status("x", (), enabled=True, section={}),
            "connected",
        )

    @patch("api.views.connectors.get_secret", return_value="s3cr3t")
    def test_connected_with_nested_dotted_required_secret(self, mock_secret):
        """Regression test for the misp-shaped bug: a required secret field
        nested under a dotted key (e.g. "instances.primary.api_key") must
        resolve correctly even though `section` never carries it."""
        nested_schema = (
            ConfigField("instances.primary.url", "url", required=True),
            ConfigField("instances.primary.api_key", "secret", required=True),
        )
        self.assertEqual(
            _compute_status(
                "misp", nested_schema, enabled=True,
                section={"instances": {"primary": {"url": "https://misp.example"}}},
            ),
            "connected",
        )
        mock_secret.assert_called_with("integrations.misp.instances.primary.api_key")
