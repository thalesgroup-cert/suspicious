"""Unit tests for connectors.bootstrap.seed_connector_secrets_from_settings."""
import os
from contextlib import ExitStack
from unittest import mock

from django.test import SimpleTestCase

from connectors import bootstrap
from connectors.base import ConfigField


class _Manifest:
    def __init__(self, fields):
        self.config_schema = tuple(fields)


class _Conn:
    def __init__(self, *fields):
        self.manifest = _Manifest(fields)


class SeedConnectorSecretsTest(SimpleTestCase):
    def _seed(self, registry_map, settings, vault, vault_addr="http://vault:8200"):
        """Run the seeder with everything mocked; return the dict of writes."""
        set_calls = {}

        def fake_get(key, default=None, *a, **k):
            return vault.get(key, default)

        def fake_set(key, value):
            set_calls[key] = value
            vault[key] = value

        def fake_settings_get(key, default=None):
            return settings.get(key, default)

        env = {} if vault_addr is None else {"VAULT_ADDR": vault_addr}
        with ExitStack() as stack:
            stack.enter_context(mock.patch.dict(os.environ, env, clear=False))
            if vault_addr is None:
                os.environ.pop("VAULT_ADDR", None)
            stack.enter_context(
                mock.patch("connectors.registry.registry.all", return_value=registry_map)
            )
            stack.enter_context(
                mock.patch("suspicious.secrets.get_secret", side_effect=fake_get)
            )
            stack.enter_context(
                mock.patch("suspicious.secrets.set_secret", side_effect=fake_set)
            )
            stack.enter_context(
                mock.patch(
                    "suspicious._config_common.settings_get", side_effect=fake_settings_get
                )
            )
            bootstrap.seed_connector_secrets_from_settings()
        return set_calls

    def test_seeds_missing_secret_from_settings(self):
        reg = {"watcher": _Conn(ConfigField(key="api_key", type="secret"))}
        calls = self._seed(reg, {"integrations.watcher.api_key": "WKEY"}, {})
        self.assertEqual(calls, {"integrations.watcher.api_key": "WKEY"})

    def test_does_not_clobber_existing_vault_value(self):
        reg = {"watcher": _Conn(ConfigField(key="api_key", type="secret"))}
        calls = self._seed(
            reg,
            {"integrations.watcher.api_key": "FROMFILE"},
            {"integrations.watcher.api_key": "FROMUI"},
        )
        self.assertEqual(calls, {})

    def test_seeds_when_vault_value_empty(self):
        reg = {"watcher": _Conn(ConfigField(key="api_key", type="secret"))}
        calls = self._seed(
            reg,
            {"integrations.watcher.api_key": "WKEY"},
            {"integrations.watcher.api_key": ""},
        )
        self.assertEqual(calls, {"integrations.watcher.api_key": "WKEY"})

    def test_skips_blank_settings_value(self):
        reg = {"watcher": _Conn(ConfigField(key="api_key", type="secret"))}
        calls = self._seed(reg, {"integrations.watcher.api_key": ""}, {})
        self.assertEqual(calls, {})

    def test_only_secret_fields_are_seeded(self):
        reg = {
            "watcher": _Conn(
                ConfigField(key="url", type="str"),
                ConfigField(key="api_key", type="secret"),
            )
        }
        calls = self._seed(
            reg,
            {
                "integrations.watcher.url": "https://x",
                "integrations.watcher.api_key": "K",
            },
            {},
        )
        self.assertEqual(calls, {"integrations.watcher.api_key": "K"})

    def test_noop_without_vault_addr(self):
        reg = {"watcher": _Conn(ConfigField(key="api_key", type="secret"))}
        calls = self._seed(
            reg, {"integrations.watcher.api_key": "K"}, {}, vault_addr=None
        )
        self.assertEqual(calls, {})
