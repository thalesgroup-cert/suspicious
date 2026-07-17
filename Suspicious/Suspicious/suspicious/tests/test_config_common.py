import json

from suspicious import _config_common as cc


def test_load_settings_reads_path(tmp_path, monkeypatch):
    p = tmp_path / "settings.json"
    p.write_text(json.dumps({"app": {"secret_key": "abc"}}))
    monkeypatch.setenv("SUSPICIOUS_CONFIG_PATH", str(p))
    cc.load_settings.cache_clear()
    assert cc.load_settings()["app"]["secret_key"] == "abc"


def test_dotted_get_walks_nested_keys():
    data = {"integrations": {"cortex": {"api_key": "k"}}}
    assert cc.dotted_get(data, "integrations.cortex.api_key") == "k"


def test_dotted_get_missing_returns_default():
    assert cc.dotted_get({"a": {}}, "a.b.c", default="x") == "x"


def test_settings_get_resolves_dotted_against_file(tmp_path, monkeypatch):
    p = tmp_path / "settings.json"
    p.write_text(json.dumps({"app": {"secret_key": "xyz"}}))
    monkeypatch.setenv("SUSPICIOUS_CONFIG_PATH", str(p))
    cc.load_settings.cache_clear()
    assert cc.settings_get("app.secret_key") == "xyz"
    assert cc.settings_get("app.missing", default="d") == "d"
