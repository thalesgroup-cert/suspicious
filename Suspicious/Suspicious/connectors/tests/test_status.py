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
            _compute_status(self.schema, enabled=False, section={"url": "x", "api_key": "y"}),
            "disabled",
        )

    def test_partial_when_required_field_missing(self):
        self.assertEqual(
            _compute_status(self.schema, enabled=True, section={"url": "x"}),
            "partial",
        )

    def test_connected_when_all_required_filled(self):
        self.assertEqual(
            _compute_status(self.schema, enabled=True, section={"url": "x", "api_key": "y"}),
            "connected",
        )

    def test_connected_when_no_required_fields(self):
        self.assertEqual(
            _compute_status((), enabled=True, section={}),
            "connected",
        )
