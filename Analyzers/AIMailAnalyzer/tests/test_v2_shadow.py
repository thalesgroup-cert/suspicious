"""Task 1 of Plan F: classify scores the active and a shadow version in one call, the shadow
isolated (an error or a timeout there never fails the request). Fixtures come from the reload tests."""
import logging
import time

import pytest

pytest.importorskip("torch")
pytest.importorskip("sentence_transformers")
pytest.importorskip("fastapi")

from inference_server import bundles, server, v2  # noqa: E402
from test_inference_server import BODY  # noqa: E402
from test_inference_server_reload import (  # noqa: E402,F401
    TokenVectorizer, app, classify, make_bundle, reload, token_env)

URL = "/v2/models/ai_mail/classify"


def post(client, headers, **body):
    return client.post(URL, json={"mail_body": BODY, **body}, headers=headers)


@pytest.fixture
def both(app, token_env, tmp_path):
    client, holder, storage, _ = app
    a, _ = make_bundle(tmp_path, storage, version="v-a")
    s, _ = make_bundle(tmp_path, storage, version="v-s")
    assert reload(client, token_env, active=a, shadow=s).status_code == 200
    return client, holder, token_env


def test_active_and_shadow_each_carry_their_version(both):
    client, holder, h = both
    out = classify(client, h, versions=["active", "shadow"])
    assert out["results"]["active"]["version"] == "v-a"
    assert out["results"]["shadow"]["version"] == "v-s"
    assert out["campaign_embedding"] == classify(client, h)["campaign_embedding"]


def test_shadow_only(both):
    client, _, h = both
    out = classify(client, h, versions=["shadow"])
    assert list(out["results"]) == ["shadow"] and out["results"]["shadow"]["version"] == "v-s"


def test_active_only_is_the_old_answer(both):
    client, _, h = both
    one, two = classify(client, h), classify(client, h, versions=["active"])
    for o in (one, two):
        o.pop("latency_ms")
    assert one == two and list(one["results"]) == ["active"]


@pytest.mark.parametrize("versions", [["bogus"], ["active", "active"], [], ["active", "x"],
                                      ["shadow", "active"]])
def test_bad_versions_are_400(both, versions):
    client, _, h = both
    assert post(client, h, versions=versions).status_code == 400


def test_shadow_only_without_shadow_is_409(app, token_env, tmp_path):
    client, _, storage, _ = app
    a, _ = make_bundle(tmp_path, storage, version="v-a")
    assert reload(client, token_env, active=a).status_code == 200
    assert post(client, token_env, versions=["shadow"]).status_code == 409


def _break_shadow(monkeypatch, fn):
    real = bundles.classify_bundle

    def wrapper(model, vectorizer, body, slots, **kw):
        if model.version_id == "v-s":
            return fn(slots)
        return real(model, vectorizer, body, slots, **kw)

    monkeypatch.setattr(bundles, "classify_bundle", wrapper)


def test_shadow_exception_is_isolated_and_leaks_nothing(both, monkeypatch, caplog):
    client, _, h = both
    base = classify(client, h)["results"]["active"]

    def boom(slots):
        raise RuntimeError(f"secret {BODY}")

    _break_shadow(monkeypatch, boom)
    with caplog.at_level(logging.DEBUG):
        r = post(client, h, versions=["active", "shadow"])
    assert r.status_code == 200
    assert r.json()["results"]["shadow"] == {"error": "RuntimeError"}
    assert r.json()["results"]["active"] == base
    assert "secret" not in r.text and "secret" not in caplog.text


def test_slow_shadow_times_out_and_frees_its_slot(both, monkeypatch):
    client, _, h = both
    monkeypatch.setattr(v2, "SHADOW_TIMEOUT", 0.05)

    def slow(slots):
        with slots:
            time.sleep(0.4)

    _break_shadow(monkeypatch, slow)
    r = post(client, h, versions=["active", "shadow"])
    assert r.status_code == 200
    assert r.json()["results"]["shadow"] == {"error": "Timeout"}
    assert r.json()["results"]["active"]["version"] == "v-a"
    slots = server._inference_slots
    assert slots.free < slots._max  # the thread still holds it
    for _ in range(100):
        if slots.free == slots._max:
            break
        time.sleep(0.05)
    assert slots.free == slots._max


def test_exclude_case_ids_apply_to_both(both, monkeypatch):
    client, _, h = both
    seen = []
    real = bundles.classify_bundle

    def spy(model, vectorizer, body, slots, **kw):
        seen.append((model.version_id, kw["exclude_case_ids"]))
        return real(model, vectorizer, body, slots, **kw)

    monkeypatch.setattr(bundles, "classify_bundle", spy)
    classify(client, h, versions=["active", "shadow"], exclude_case_ids=[101])
    assert sorted(seen) == [("v-a", [101]), ("v-s", [101])]
