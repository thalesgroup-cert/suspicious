from django.test import SimpleTestCase

from connectors.base import EVENT_CASE_FINALISED
from connectors.registry import ConnectorRegistry
from connectors.tests.dummy import DummyConnector


class RegistryTest(SimpleTestCase):
    def setUp(self):
        self.registry = ConnectorRegistry()

    def test_register_and_lookup(self):
        self.registry.register(DummyConnector)
        self.assertIs(self.registry.get("dummy"), DummyConnector)
        self.assertEqual(self.registry.names(), ["dummy"])

    def test_duplicate_name_rejected(self):
        self.registry.register(DummyConnector)
        with self.assertRaises(ValueError):
            self.registry.register(DummyConnector)

    def test_subscribers_filters_by_event(self):
        self.registry.register(DummyConnector)
        self.assertEqual(self.registry.subscribers(EVENT_CASE_FINALISED), ["dummy"])
        self.assertEqual(self.registry.subscribers("case_created"), [])

    def test_scheduled_lists_manifest_schedules(self):
        self.registry.register(DummyConnector)
        [(name, sched)] = self.registry.scheduled()
        self.assertEqual((name, sched.interval_seconds), ("dummy", 120))

    def test_register_contributes_scope_and_secrets(self):
        from settings.config import SCOPE_SECTIONS, SECRET_FIELDS
        self.registry.register(DummyConnector)
        self.assertIn("integrations.dummy", SCOPE_SECTIONS["backend"])
        self.assertIn("api_key", SECRET_FIELDS["integrations.dummy"])
        # dotted secret key lands in the nested section
        self.assertIn("token", SECRET_FIELDS["integrations.dummy.nested.deep"])

    def test_register_creates_breaker(self):
        from common.http_client import BREAKERS
        self.registry.register(DummyConnector)
        self.assertIn("dummy", BREAKERS)

    def test_load_failure_recorded_not_raised(self):
        self.registry._load("connectors.no_such_module:Nope", builtin=True)
        self.assertIn("connectors.no_such_module:Nope", self.registry.errors)
