from unittest import mock

from django.test import SimpleTestCase

from connectors.contrib.thehive.connector import TheHiveConnector


class TheHiveConnectorTest(SimpleTestCase):
    def test_manifest(self):
        m = TheHiveConnector.manifest
        m.validate()
        self.assertEqual(m.name, "thehive")
        self.assertEqual(m.events, ("case_finalised",))

    def test_health_check_unconfigured(self):
        status = TheHiveConnector({}).health_check()
        self.assertFalse(status.ok)

    def test_health_check_ok(self):
        connector = TheHiveConnector({"url": "https://hive", "api_key": "k"})
        with mock.patch("connectors.contrib.thehive.connector.make_session") as ms:
            ms.return_value.get.return_value.raise_for_status.return_value = None
            self.assertTrue(connector.health_check().ok)


class HealthPermissionsTest(SimpleTestCase):
    """An expired TheHive trial silently drops manageAlert/update and
    manageObservable; every attachment/observable upload then answers 403."""

    def _health(self, permissions):
        connector = TheHiveConnector({"url": "https://hive", "api_key": "k"})
        with mock.patch("connectors.contrib.thehive.connector.make_session") as ms:
            resp = ms.return_value.get.return_value
            resp.raise_for_status.return_value = None
            resp.json.return_value = {"login": "svc", "permissions": permissions}
            return connector.health_check()

    def test_missing_write_permissions_are_reported(self):
        status = self._health(["manageAlert/create", "manageUser"])
        self.assertFalse(status.ok)
        self.assertIn("manageAlert/update", status.detail)
        self.assertIn("manageObservable", status.detail)
        self.assertNotIn("manageAlert/create", status.detail)

    def test_full_permissions_are_ok(self):
        status = self._health(["manageAlert/create", "manageAlert/update", "manageObservable"])
        self.assertTrue(status.ok)
