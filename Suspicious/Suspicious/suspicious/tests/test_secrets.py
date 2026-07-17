"""Unit tests for suspicious.secrets — plain unittest so the Django test
runner (and the Docker image, which ships without pytest) can run them."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from suspicious import secrets as sec


class SecretsTestCase(unittest.TestCase):
    def setUp(self):
        sec._CACHE.clear()
        sec._client_singleton[0] = None
        self.addCleanup(sec._CACHE.clear)
        self.addCleanup(lambda: sec._client_singleton.__setitem__(0, None))

    def _set_env(self, **env):
        """Patch os.environ for the duration of the test. A value of None
        removes the variable."""
        removed = [k for k, v in env.items() if v is None]
        added = {k: v for k, v in env.items() if v is not None}
        patcher = mock.patch.dict(os.environ, added)
        patcher.start()
        self.addCleanup(patcher.stop)
        for key in removed:
            os.environ.pop(key, None)

    def test_dev_fallback_reads_settings_json(self):
        self._set_env(VAULT_ADDR=None)
        tmp_dir = tempfile.mkdtemp()
        self.addCleanup(lambda: os.remove(os.path.join(tmp_dir, "settings.json")))
        p = Path(tmp_dir) / "settings.json"
        p.write_text(json.dumps({"integrations": {"cortex": {"api_key": "DEVKEY"}}}))
        self._set_env(SUSPICIOUS_CONFIG_PATH=str(p))
        from suspicious import _config_common as cc
        cc.load_settings.cache_clear()
        self.addCleanup(cc.load_settings.cache_clear)
        self.assertEqual(sec.get_secret("integrations.cortex.api_key"), "DEVKEY")

    def test_vault_read_uses_kv_v2(self):
        self._set_env(
            VAULT_ADDR="http://vault:8200", VAULT_ROLE_ID="r", VAULT_SECRET_ID="s",
        )
        test = self

        class FakeKV2:
            def read_secret_version(self, path, mount_point, raise_on_deleted_version=True):
                test.assertEqual(mount_point, "suspicious")
                test.assertEqual(path, "database.password")
                return {"data": {"data": {"value": "VAULTPW"}}}

        class FakeClient:
            def __init__(self, *a, **k):
                self.secrets = type("S", (), {"kv": type("K", (), {"v2": FakeKV2()})()})()
                self.auth = type("A", (), {"approle": type("R", (), {
                    "login": staticmethod(lambda role_id, secret_id: None)})()})()

            def is_authenticated(self):
                return True

        with mock.patch.object(sec, "_make_client", FakeClient):
            self.assertEqual(sec.get_secret("database.password"), "VAULTPW")

    def test_vault_caches_in_process(self):
        self._set_env(VAULT_ADDR="http://vault:8200")
        calls = {"n": 0}

        def fake_read(key):
            calls["n"] += 1
            return "v"

        with mock.patch.object(sec, "_read_from_vault", fake_read):
            self.assertEqual(sec.get_secret("app.secret_key"), "v")
            self.assertEqual(sec.get_secret("app.secret_key"), "v")
        self.assertEqual(calls["n"], 1)

    def test_boot_fail_fast_when_vault_unreachable(self):
        self._set_env(VAULT_ADDR="http://vault:8200")

        def boom(key):
            raise RuntimeError("connection refused")

        with mock.patch.object(sec, "_read_from_vault", boom):
            with self.assertRaises(SystemExit):
                sec.get_secret("app.secret_key", fail_fast=True)

    def test_missing_vault_key_returns_default(self):
        import hvac

        self._set_env(VAULT_ADDR="http://vault:8200")

        def not_found(key):
            raise hvac.exceptions.InvalidPath("no value found at suspicious/data/...")

        with mock.patch.object(sec, "_read_from_vault", not_found):
            self.assertEqual(sec.get_secret("integrations.thehive.api_key", ""), "")
            self.assertEqual(
                sec.get_secret("authentication.oidc.client_secret", "fallback"),
                "fallback",
            )

    def test_set_secret_without_vault_raises(self):
        self._set_env(VAULT_ADDR=None)
        with self.assertRaises(sec.SecretStoreUnavailable):
            sec.set_secret("integrations.watcher.api_key", "NEW")

    def test_set_secret_writes_vault_and_updates_cache(self):
        self._set_env(VAULT_ADDR="http://vault:8200")
        written = {}

        class FakeKV2:
            def create_or_update_secret(self, path, secret, mount_point):
                written["path"] = path
                written["secret"] = secret
                written["mount_point"] = mount_point

        class FakeClient:
            secrets = type("S", (), {"kv": type("K", (), {"v2": FakeKV2()})()})()

        with mock.patch.object(sec, "_client", FakeClient):
            sec.set_secret("integrations.watcher.api_key", "NEW")

        self.assertEqual(written["path"], "integrations.watcher.api_key")
        self.assertEqual(written["secret"], {"value": "NEW"})
        self.assertEqual(written["mount_point"], "suspicious")
        with mock.patch.object(sec, "_read_from_vault",
                               side_effect=AssertionError("should not read")):
            self.assertEqual(sec.get_secret("integrations.watcher.api_key"), "NEW")

    def test_cache_entry_expires_after_ttl(self):
        self._set_env(VAULT_ADDR="http://vault:8200")
        calls = {"n": 0}

        def fake_read(key):
            calls["n"] += 1
            return f"v{calls['n']}"

        with mock.patch.object(sec, "_read_from_vault", fake_read):
            t = [1000.0]
            with mock.patch.object(sec.time, "monotonic", lambda: t[0]):
                self.assertEqual(sec.get_secret("app.secret_key"), "v1")
                t[0] += 5
                self.assertEqual(sec.get_secret("app.secret_key"), "v1")
                t[0] += 60
                self.assertEqual(sec.get_secret("app.secret_key"), "v2")
        self.assertEqual(calls["n"], 2)
