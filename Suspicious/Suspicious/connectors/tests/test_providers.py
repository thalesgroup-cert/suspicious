from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase
from rest_framework.test import APITestCase

from connectors.base import (
    ConnectorManifest,
    PROVIDER_KIND_MAIL_AI,
    ProviderResult,
)
from connectors.delivery import get_state
from connectors.models import ConnectorState
from connectors.providers import enabled_provider
from connectors.registry import ConnectorRegistry
from connectors.tests.dummy import DummyConnector, DummyProviderConnector


class OtherProviderConnector(DummyProviderConnector):
    manifest = ConnectorManifest(
        name="other_provider", version="0.0.1", provides=PROVIDER_KIND_MAIL_AI,
    )


def make_registry():
    registry = ConnectorRegistry()
    for cls in (DummyConnector, DummyProviderConnector, OtherProviderConnector):
        registry.register(cls)
    return registry


class ManifestAndBaseTest(TestCase):
    def test_unknown_provides_fails_validation(self):
        with self.assertRaises(ValueError):
            ConnectorManifest(name="x1", version="1", provides="nope").validate()

    def test_known_or_empty_provides_validates(self):
        ConnectorManifest(name="x1", version="1").validate()
        ConnectorManifest(name="x1", version="1", provides="mail_ai").validate()

    def test_analyze_is_not_implemented_by_default(self):
        with self.assertRaises(NotImplementedError):
            DummyConnector({}).analyze("mail_ai", 1)

    def test_provider_result_is_frozen(self):
        result = ProviderResult("SAFE", 0.1, 90.0, "Ham", "v1", {})
        self.assertEqual(result.reason, "")
        with self.assertRaises(Exception):
            result.score = 0.5

    def test_dummy_provider_analyze_returns_result_or_raises(self):
        result = ProviderResult("SAFE", 0.1, 90.0, "Ham", "v1", {})
        DummyProviderConnector.result, DummyProviderConnector.error = result, None
        self.addCleanup(setattr, DummyProviderConnector, "result", None)
        self.assertIs(DummyProviderConnector({}).analyze("mail_ai", 1), result)
        DummyProviderConnector.error = RuntimeError("boom")
        self.addCleanup(setattr, DummyProviderConnector, "error", None)
        with self.assertRaises(RuntimeError):
            DummyProviderConnector({}).analyze("mail_ai", 1)


class ProviderLookupTest(TestCase):
    def setUp(self):
        self.registry = make_registry()
        patcher = mock.patch("connectors.providers.registry", self.registry)
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch("connectors.delivery.registry", self.registry)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_registry_providers_lists_only_matching_kind(self):
        self.assertEqual(
            self.registry.providers("mail_ai"), ["dummy_provider", "other_provider"]
        )
        self.assertEqual(self.registry.providers("nope"), [])

    def test_enabled_provider_is_none_unless_enabled(self):
        ConnectorState.objects.create(name="dummy_provider", enabled=False)
        ConnectorState.objects.create(name="other_provider", enabled=False)
        self.assertIsNone(enabled_provider("mail_ai"))
        ConnectorState.objects.filter(name="dummy_provider").update(enabled=True)
        self.assertEqual(enabled_provider("mail_ai"), "dummy_provider")

    def test_enabled_provider_ignores_enabled_non_providers(self):
        ConnectorState.objects.create(name="dummy", enabled=True)
        self.assertIsNone(enabled_provider("mail_ai"))


class ProviderEnableGuardApiTest(APITestCase):
    def setUp(self):
        self.registry = make_registry()
        for target in (
            "api.views.connectors.registry",
            "connectors.delivery.registry",
            "connectors.providers.registry",
        ):
            patcher = mock.patch(target, self.registry)
            patcher.start()
            self.addCleanup(patcher.stop)
        user = get_user_model().objects.create_user(username="admin", password="x")
        user.groups.add(Group.objects.get_or_create(name="Admin")[0])
        self.client.force_authenticate(user)

    def patch_enabled(self, name, enabled):
        return self.client.patch(f"/api/connectors/{name}/", {"enabled": enabled}, format="json")

    def test_enabling_a_second_provider_of_the_same_kind_is_409(self):
        ConnectorState.objects.create(name="dummy_provider", enabled=True)
        response = self.patch_enabled("other_provider", True)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(
            response.json(), {"detail": "other_provider already provides mail_ai"}
        )
        self.assertFalse(get_state("other_provider").enabled)

    def test_disabling_and_enabling_the_same_provider_is_fine(self):
        self.assertEqual(self.patch_enabled("dummy_provider", True).status_code, 200)
        self.assertEqual(self.patch_enabled("dummy_provider", True).status_code, 200)
        self.assertEqual(self.patch_enabled("dummy_provider", False).status_code, 200)
        self.assertEqual(self.patch_enabled("dummy_provider", True).status_code, 200)

    def test_second_provider_can_be_enabled_after_the_first_is_disabled(self):
        self.patch_enabled("dummy_provider", True)
        self.patch_enabled("dummy_provider", False)
        self.assertEqual(self.patch_enabled("other_provider", True).status_code, 200)

    def test_non_provider_is_unaffected_by_an_enabled_provider(self):
        ConnectorState.objects.create(name="dummy_provider", enabled=True)
        self.assertEqual(self.patch_enabled("dummy", True).status_code, 200)
