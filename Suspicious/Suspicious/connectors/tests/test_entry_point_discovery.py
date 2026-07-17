from unittest import mock

from django.test import SimpleTestCase

from connectors.registry import ConnectorRegistry
from connectors.tests.dummy import DummyConnector


class FakeEntryPoint:
    name = "dummy_ep"

    def load(self):
        return DummyConnector


class BrokenEntryPoint:
    name = "broken_ep"

    def load(self):
        raise ImportError("missing dependency")


class EntryPointDiscoveryTest(SimpleTestCase):
    def test_discovers_and_isolates_entry_points(self):
        registry = ConnectorRegistry()
        with mock.patch(
            "connectors.registry.metadata.entry_points",
            return_value=[FakeEntryPoint(), BrokenEntryPoint()],
        ), mock.patch("connectors.contrib.BUILTIN_CONNECTOR_PATHS", ()):
            registry.discover()
        self.assertIn("dummy", registry.names())
        self.assertIn("broken_ep", registry.errors)
