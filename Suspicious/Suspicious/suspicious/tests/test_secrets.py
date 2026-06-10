import pytest

from suspicious import secrets as sec


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    sec._CACHE.clear()
    sec._client_singleton[0] = None
    yield
    sec._CACHE.clear()
    sec._client_singleton[0] = None


def test_dev_fallback_reads_settings_json(monkeypatch, tmp_path):
    monkeypatch.delenv("VAULT_ADDR", raising=False)
    import json
    p = tmp_path / "settings.json"
    p.write_text(json.dumps({"integrations": {"cortex": {"api_key": "DEVKEY"}}}))
    monkeypatch.setenv("SUSPICIOUS_CONFIG_PATH", str(p))
    from suspicious import _config_common as cc
    cc.load_settings.cache_clear()
    assert sec.get_secret("integrations.cortex.api_key") == "DEVKEY"


def test_vault_read_uses_kv_v2(monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", "http://vault:8200")
    monkeypatch.setenv("VAULT_ROLE_ID", "r")
    monkeypatch.setenv("VAULT_SECRET_ID", "s")

    class FakeKV2:
        def read_secret_version(self, path, mount_point, raise_on_deleted_version=True):
            assert mount_point == "suspicious"
            assert path == "database.password"
            return {"data": {"data": {"value": "VAULTPW"}}}

    class FakeClient:
        def __init__(self, *a, **k):
            self.secrets = type("S", (), {"kv": type("K", (), {"v2": FakeKV2()})()})()
            self.auth = type("A", (), {"approle": type("R", (), {
                "login": staticmethod(lambda role_id, secret_id: None)})()})()

        def is_authenticated(self):
            return True

    monkeypatch.setattr(sec, "_make_client", lambda: FakeClient())
    assert sec.get_secret("database.password") == "VAULTPW"


def test_vault_caches_in_process(monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", "http://vault:8200")
    calls = {"n": 0}

    def fake_read(key):
        calls["n"] += 1
        return "v"

    monkeypatch.setattr(sec, "_read_from_vault", fake_read)
    assert sec.get_secret("app.secret_key") == "v"
    assert sec.get_secret("app.secret_key") == "v"
    assert calls["n"] == 1


def test_boot_fail_fast_when_vault_unreachable(monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", "http://vault:8200")

    def boom(key):
        raise RuntimeError("connection refused")

    monkeypatch.setattr(sec, "_read_from_vault", boom)
    with pytest.raises(SystemExit):
        sec.get_secret("app.secret_key", fail_fast=True)


def test_missing_vault_key_returns_default(monkeypatch):
    # A key absent in Vault (KV v2 404 -> hvac InvalidPath) must fall through
    # to the caller default, not raise — so optional, unconfigured secrets
    # resolve to "" instead of crashing boot/requests.
    import hvac

    monkeypatch.setenv("VAULT_ADDR", "http://vault:8200")

    def not_found(key):
        raise hvac.exceptions.InvalidPath("no value found at suspicious/data/...")

    monkeypatch.setattr(sec, "_read_from_vault", not_found)
    assert sec.get_secret("integrations.thehive.api_key", "") == ""
    assert sec.get_secret("authentication.oidc.client_secret", "fallback") == "fallback"
