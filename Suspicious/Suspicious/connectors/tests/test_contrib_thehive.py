from unittest import mock

from django.test import SimpleTestCase

from connectors.contrib.thehive.connector import TheHiveConnector


class TheHiveConnectorTest(SimpleTestCase):
    def test_manifest(self):
        m = TheHiveConnector.manifest
        m.validate()
        self.assertEqual(m.name, "thehive")
        self.assertEqual(m.events, ("campaign_updated",))

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


class CampaignHookTest(SimpleTestCase):
    PATH = "connectors.contrib.thehive.connector"

    def _run(self, config):
        connector = TheHiveConnector(config)
        with mock.patch(f"{self.PATH}.Campaign") as campaign_model, \
                mock.patch(f"{self.PATH}.sync_campaign") as sync, \
                mock.patch(f"{self.PATH}.HiveClient") as client, \
                mock.patch(f"{self.PATH}.get_s3_client"), \
                mock.patch(f"{self.PATH}._email_settings", return_value=("https://sus.example", ("meridian.example",))):
            connector.on_campaign_updated(mock.Mock(campaign_id=4))
        return campaign_model, sync, client

    def test_syncs_the_campaign_with_the_configured_certificate(self):
        campaign_model, sync, client = self._run(
            {"url": "https://hive", "api_key": "k", "certificate_path": "/etc/ca.pem"})
        client.assert_called_once_with("https://hive", "k", verify="/etc/ca.pem")
        campaign_model.objects.get.assert_called_once_with(pk=4)
        sync.assert_called_once()
        self.assertEqual(sync.call_args.kwargs["ui_base"], "https://sus.example")
        self.assertEqual(sync.call_args.kwargs["own_domains"], ("meridian.example",))

    def test_system_trust_store_when_no_certificate_is_configured(self):
        _model, _sync, client = self._run({"url": "https://hive", "api_key": "k"})
        client.assert_called_once_with("https://hive", "k", verify=True)

    def test_unconfigured_connector_does_nothing(self):
        _model, sync, client = self._run({})
        sync.assert_not_called()
        client.assert_not_called()
