from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from rest_framework.test import APITestCase

from connectors.models import ConnectorDelivery, ConnectorState
from connectors.registry import ConnectorRegistry
from connectors.tests.dummy import DummyConnector


def make_registry():
    registry = ConnectorRegistry()
    registry.register(DummyConnector)
    return registry


class ConnectorsApiTest(APITestCase):
    def setUp(self):
        self.registry = make_registry()
        for target in (
            "api.views.connectors.registry",
            "connectors.delivery.registry",
        ):
            patcher = mock.patch(target, self.registry)
            patcher.start()
            self.addCleanup(patcher.stop)
        user = get_user_model().objects.create_user(username="admin", password="x")
        user.groups.add(Group.objects.get_or_create(name="Admin")[0])
        self.client.force_authenticate(user)

    def test_list_includes_manifest_and_state(self):
        ConnectorState.objects.create(name="dummy", enabled=True)
        response = self.client.get("/api/connectors/")
        self.assertEqual(response.status_code, 200)
        [item] = [c for c in response.json()["connectors"] if c["name"] == "dummy"]
        self.assertTrue(item["enabled"])
        self.assertEqual(item["version"], "0.0.1")
        self.assertEqual(item["config_schema"][0]["key"], "url")

    def test_list_forbidden_for_plain_user(self):
        plain = get_user_model().objects.create_user(username="u", password="x")
        self.client.force_authenticate(plain)
        self.assertEqual(self.client.get("/api/connectors/").status_code, 403)

    def test_patch_toggles_enabled(self):
        response = self.client.patch(
            "/api/connectors/dummy/", {"enabled": True}, format="json"
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(ConnectorState.objects.get(name="dummy").enabled)

    def test_patch_rejects_non_boolean(self):
        response = self.client.patch(
            "/api/connectors/dummy/", {"enabled": "yes"}, format="json"
        )
        self.assertEqual(response.status_code, 400)

    def test_unknown_connector_404(self):
        self.assertEqual(
            self.client.patch("/api/connectors/nope/", {"enabled": True},
                              format="json").status_code,
            404,
        )

    def test_config_get_masks_secrets(self):
        with mock.patch(
            "api.views.connectors.get_section",
            return_value={"url": "http://x", "api_key": "topsecret"},
        ):
            response = self.client.get("/api/connectors/dummy/config/")
        self.assertEqual(response.json()["config"]["api_key"], "********")
        self.assertEqual(response.json()["config"]["url"], "http://x")

    def test_config_put_writes_secret_to_vault(self):
        from settings.models import RuntimeConfig
        with mock.patch("api.views.connectors.set_secret") as set_secret:
            response = self.client.put(
                "/api/connectors/dummy/config/",
                {"url": "http://x", "api_key": "topsecret"}, format="json",
            )
        self.assertEqual(response.status_code, 200)
        set_secret.assert_called_once_with(
            "integrations.dummy.api_key", "topsecret"
        )
        row = RuntimeConfig.objects.get(key="integrations.dummy")
        self.assertNotIn("api_key", row.value)
        self.assertEqual(row.value["url"], "http://x")
        self.assertEqual(response.json()["config"]["api_key"], "********")

    def test_config_put_writes_nested_secret_to_vault(self):
        from settings.models import RuntimeConfig
        with mock.patch("api.views.connectors.set_secret") as set_secret:
            response = self.client.put(
                "/api/connectors/dummy/config/",
                {"url": "http://x", "nested": {"deep": {"token": "s3cr3t"}}},
                format="json",
            )
        self.assertEqual(response.status_code, 200)
        set_secret.assert_called_once_with(
            "integrations.dummy.nested.deep.token", "s3cr3t"
        )
        row = RuntimeConfig.objects.get(key="integrations.dummy")
        self.assertNotIn("token", row.value.get("nested", {}).get("deep", {}))
        self.assertEqual(
            response.json()["config"]["nested"]["deep"]["token"], "********"
        )

    def test_config_put_skips_masked_secret(self):
        with mock.patch("api.views.connectors.set_secret") as set_secret:
            response = self.client.put(
                "/api/connectors/dummy/config/",
                {"url": "http://x", "api_key": "********"}, format="json",
            )
        self.assertEqual(response.status_code, 200)
        set_secret.assert_not_called()

    def test_config_put_secret_store_unavailable_returns_409(self):
        from suspicious.secrets import SecretStoreUnavailable
        with mock.patch("api.views.connectors.set_secret",
                        side_effect=SecretStoreUnavailable("no vault")):
            response = self.client.put(
                "/api/connectors/dummy/config/",
                {"url": "http://x", "api_key": "topsecret"}, format="json",
            )
        self.assertEqual(response.status_code, 409)
        self.assertIn("api_key", response.json()["errors"])

    def test_config_put_secret_write_failure_returns_502(self):
        with mock.patch("api.views.connectors.set_secret",
                        side_effect=RuntimeError("permission denied")):
            response = self.client.put(
                "/api/connectors/dummy/config/",
                {"url": "http://x", "api_key": "topsecret"}, format="json",
            )
        self.assertEqual(response.status_code, 502)
        self.assertIn("api_key", response.json()["errors"])

    def test_config_put_no_vault_write_when_validation_fails(self):
        with mock.patch("api.views.connectors.set_secret") as set_secret:
            response = self.client.put(
                "/api/connectors/dummy/config/",
                {"api_key": "topsecret"}, format="json",
            )
        self.assertEqual(response.status_code, 400)
        set_secret.assert_not_called()

    def test_config_put_writes_runtimeconfig(self):
        from settings.models import RuntimeConfig
        response = self.client.put(
            "/api/connectors/dummy/config/", {"url": "http://new"}, format="json",
        )
        self.assertEqual(response.status_code, 200)
        row = RuntimeConfig.objects.get(key="integrations.dummy")
        self.assertEqual(row.value["url"], "http://new")

    def test_config_put_validates_required(self):
        response = self.client.put(
            "/api/connectors/dummy/config/", {}, format="json",
        )
        self.assertEqual(response.status_code, 400)

    def test_test_endpoint_runs_health_check(self):
        ConnectorState.objects.create(name="dummy", enabled=True)
        with mock.patch.object(
            self.registry, "instantiate", return_value=DummyConnector({"url": "x"})
        ):
            response = self.client.post("/api/connectors/dummy/test/")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["ok"])
        state = ConnectorState.objects.get(name="dummy")
        self.assertTrue(state.last_health_ok)

    def test_deliveries_paginated(self):
        for _ in range(3):
            ConnectorDelivery.objects.create(
                connector="dummy", event="case_finalised", status="success"
            )
        response = self.client.get("/api/connectors/dummy/deliveries/?limit=2")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()["results"]), 2)
