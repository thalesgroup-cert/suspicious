from unittest import mock

from django.test import SimpleTestCase

from connectors.contrib.thehive.connector import TheHiveConnector


class TheHiveConnectorTest(SimpleTestCase):
    def test_manifest(self):
        m = TheHiveConnector.manifest
        m.validate()
        self.assertEqual(m.name, "thehive")
        self.assertEqual(m.events, ())

    def test_health_check_unconfigured(self):
        status = TheHiveConnector({}).health_check()
        self.assertFalse(status.ok)

    def test_health_check_ok(self):
        connector = TheHiveConnector({"url": "https://hive", "api_key": "k"})
        with mock.patch("connectors.contrib.thehive.connector.make_session") as ms:
            ms.return_value.get.return_value.raise_for_status.return_value = None
            self.assertTrue(connector.health_check().ok)
