import importlib
import sys


def test_settings_import_with_vault(monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", "http://vault:8200")
    from suspicious import secrets as sec

    def fake_secret(key, default=None, *, fail_fast=False):
        return {"app.secret_key": "x" * 60, "database.password": "pw"}.get(key, default)

    monkeypatch.setattr(sec, "get_secret", fake_secret)
    sys.modules.pop("suspicious.settings", None)
    mod = importlib.import_module("suspicious.settings")
    assert mod.SECRET_KEY == "x" * 60


def test_settings_import_without_vault_uses_json(monkeypatch):
    monkeypatch.delenv("VAULT_ADDR", raising=False)
    sys.modules.pop("suspicious.settings", None)
    mod = importlib.import_module("suspicious.settings")
    assert mod.SECRET_KEY
