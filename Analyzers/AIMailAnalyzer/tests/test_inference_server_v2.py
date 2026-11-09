"""
Tests for the token-protected /v2 API of inference_server (v2.py + auth.py).

Same approach as test_inference_server.py: the real FastAPI app and the real
torch loading path, only the sentence-transformer is faked. The weight-writing
helpers and FakeVectorizer are imported from that module rather than copied.
"""
import pytest

pytest.importorskip("torch")
pytest.importorskip("sentence_transformers")
pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from inference_server import server  # noqa: E402
from test_inference_server import BODY, FakeVectorizer, write_models  # noqa: E402

TOKEN = "s3cret-test-token"


@pytest.fixture
def make_client(tmp_path, monkeypatch):
    """Factory: the real server.app against temp model dirs."""
    clients = []

    def make(personal=True):
        dirs = {"personal": tmp_path / "models"}
        for directory in dirs.values():
            directory.mkdir()
        if personal:
            write_models(dirs["personal"], seed=1)
        monkeypatch.setattr(server, "MODEL_DIRS", dirs)
        # The v2 router captured server.store at import time: reset that same object in place.
        monkeypatch.setattr(server.store, "__dict__", server.ModelStore(dirs).__dict__)
        monkeypatch.setattr(server, "SentenceTransformer", FakeVectorizer)
        monkeypatch.setattr(server, "RELOAD_CHECK_SECONDS", 0)
        client = TestClient(server.app)
        client.__enter__()  # runs the lifespan (loads vectorizer + weights)
        clients.append(client)
        return client

    yield make
    for client in clients:
        client.__exit__(None, None, None)


@pytest.fixture
def client(make_client):
    return make_client()


@pytest.fixture
def client_without_models(make_client):
    return make_client(personal=False)


@pytest.fixture
def token_env(monkeypatch):
    monkeypatch.setenv("AI_INFERENCE_TOKEN", TOKEN)
    return {"Authorization": f"Bearer {TOKEN}"}


# --- health ---------------------------------------------------------------------


def test_live_needs_no_token(client):
    assert client.get("/v2/health/live").json() == {"live": True}


def test_ready_needs_no_token_and_carries_the_health_payload(client):
    resp = client.get("/v2/health/ready")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ready"] is True
    assert body["vectorizer"] == {"loaded": True, "error": None}
    assert body["variants"]["personal"]["ready"] is True


def test_ready_is_503_until_the_models_are_loaded(client_without_models):
    resp = client_without_models.get("/v2/health/ready")
    assert resp.status_code == 503
    assert resp.json()["ready"] is False
    assert resp.json()["variants"]["personal"]["ready"] is False


# --- token ------------------------------------------------------------------------


def test_metadata_is_401_without_or_with_a_wrong_token(client, token_env):
    assert client.get("/v2/models/ai_mail").status_code == 401
    assert client.get("/v2/models/ai_mail", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_metadata_is_401_for_the_right_token_under_another_scheme(client, token_env):
    assert client.get("/v2/models/ai_mail", headers={"Authorization": f"Basic {TOKEN}"}).status_code == 401
    assert client.get("/v2/models/ai_mail", headers={"Authorization": TOKEN}).status_code == 401


def test_authed_routes_fail_closed_when_no_token_is_configured(client, monkeypatch):
    monkeypatch.delenv("AI_INFERENCE_TOKEN", raising=False)
    resp = client.get("/v2/models/ai_mail", headers={"Authorization": "Bearer x"})
    assert resp.status_code == 503
    assert resp.json() == {"detail": "token not configured"}


# --- metadata -----------------------------------------------------------------------


def test_metadata_with_token(client, token_env):
    body = client.get("/v2/models/ai_mail", headers=token_env).json()
    assert body["name"] == "ai_mail"
    assert body["versions"]["active"] == {"id": "v0", "preprocessing": "legacy-first128",
                                          "campaign_embedding_version": "cmp-e1", "calibrated": False}


# --- classify (version 0) -----------------------------------------------------------


def post_v2(client, headers, body=BODY, versions=("active",), raw=False):
    resp = client.post("/v2/models/ai_mail/classify",
                       json={"mail_body": body, "versions": list(versions)}, headers=headers)
    return resp if raw else resp.json()


def test_v2_classify_maps_the_classify_core(client, token_env):
    legacy = server._classify(server.store.models("personal"), BODY)
    new = client.post("/v2/models/ai_mail/classify",
                      json={"mail_body": BODY, "versions": ["active"]}, headers=token_env).json()
    r = new["results"]["active"]
    assert r["class"] == legacy["classification"] and r["score"] == float(legacy["malscore"])
    assert r["confidence"] == float(legacy["confidence"]) and r["sub_class"] == legacy["sub_classification"]
    assert r["sub_class_confidence"] == float(legacy["sub_classification_confidence"])
    assert r["probabilities"] == legacy["classification_breakdown"]
    assert r["sub_probabilities"] == legacy["sub_classification_breakdown"]
    assert r["contributing_phrases"] == legacy["contributing_phrases"]
    assert new["campaign_embedding"] == legacy["email_embedding"]
    assert new["campaign_embedding_version"] == "cmp-e1"
    assert isinstance(new["latency_ms"], int) and new["latency_ms"] >= 0


def test_v0_has_no_tier_and_no_similar_cases(client, token_env):
    r = post_v2(client, token_env)["results"]["active"]
    assert r["tier"] is None and r["similar_cases"] == [] and r["version"] == "v0"


def test_unknown_version_is_400(client, token_env):
    assert post_v2(client, token_env, versions=["canary"], raw=True).status_code == 400
    assert post_v2(client, token_env, versions=[], raw=True).status_code == 400


def test_shadow_without_a_loaded_shadow(client, token_env):
    assert post_v2(client, token_env, versions=["shadow"], raw=True).status_code == 409
    out = post_v2(client, token_env, versions=["active", "shadow"], raw=True).json()
    assert out["results"]["shadow"] == {"error": "NoShadow"}


def test_classify_is_401_without_a_token(client, token_env):
    resp = client.post("/v2/models/ai_mail/classify", json={"mail_body": BODY, "versions": ["active"]})
    assert resp.status_code == 401


def test_a_body_far_over_max_chars_is_truncated_not_rejected(client, token_env):
    FakeVectorizer.reset()
    assert post_v2(client, token_env, body="x " * server.MAX_MAIL_CHARS, raw=True).status_code == 200
    assert FakeVectorizer.max_len_seen <= server.MAX_MAIL_CHARS


# Invisible and bidi characters are written as escapes so the source stays readable in review:
# U+200B/200C/200D zero-width space/non-joiner/joiner, U+2060 word joiner, U+FEFF BOM,
# U+202E right-to-left override, U+202C pop directional formatting.
OBFUSCATED_BODIES = {
    "zero_width_only": "\u200b\u200c\u200d\u2060\ufeff" * 200,
    "zero_width_inside_words": "Ve\u200brify y\u200dour acc\u2060ount n\ufeffow",
    "mixed_scripts": "Your раyраl αccount: الحساب "
                     "账户 \U0001f512 rіsk \u202eredli\u202c",
    "combining_marks": "a\u0301\u0302\u0303\u0304" * 500,
}


@pytest.mark.parametrize("name", sorted(OBFUSCATED_BODIES))
def test_obfuscated_unicode_bodies_are_classified_not_500(client, token_env, name):
    assert post_v2(client, token_env, body=OBFUSCATED_BODIES[name], raw=True).status_code == 200


def test_a_lone_surrogate_escape_is_never_a_500(client, token_env):
    # A JSON "\ud800" escape decodes to a lone surrogate: unencodable as UTF-8 downstream.
    resp = client.post(
        "/v2/models/ai_mail/classify",
        content=b'{"mail_body": "Verify \\ud800 your account \\udfff now", "versions": ["active"]}',
        headers={**token_env, "Content-Type": "application/json"},
    )
    assert resp.status_code == 200, resp.text


def test_503_when_models_are_missing(client_without_models, token_env):
    resp = post_v2(client_without_models, token_env, raw=True)
    assert resp.status_code == 503
    assert resp.json() == {"detail": server.store.unavailable("personal")}


def test_503_when_the_vectorizer_is_missing(client, token_env, monkeypatch):
    monkeypatch.setattr(server.store, "vectorizer", None)
    monkeypatch.setattr(server.store, "vectorizer_error", "boom")
    resp = post_v2(client, token_env, raw=True)
    assert resp.status_code == 503
    assert resp.json() == {"detail": "Vectorizer unavailable: boom"}


# --- embed ----------------------------------------------------------------------------


def post_embed(client, headers=None, texts=("a", "b"), profile="classifier"):
    return client.post("/v2/embed", json={"texts": list(texts), "profile": profile}, headers=headers or {})


def test_embed_needs_the_token(client, token_env, monkeypatch):
    assert post_embed(client).status_code == 401
    assert post_embed(client, {"Authorization": "Bearer wrong"}).status_code == 401
    monkeypatch.delenv("AI_INFERENCE_TOKEN")
    assert post_embed(client, token_env).status_code == 503


def test_embed_returns_one_768_vector_per_text(client, token_env):
    resp = post_embed(client, token_env)
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["vectors"]) == 2 and all(len(v) == 768 for v in body["vectors"])
    assert all(isinstance(x, float) for x in body["vectors"][0])
    assert body["preprocessing_version"] == "legacy-first128"
    assert body["embedding_version"] == "cmp-e1"


def test_embed_rejects_a_bad_profile_or_too_many_texts(client, token_env):
    assert post_embed(client, token_env, profile="other").status_code == 422
    assert post_embed(client, token_env, texts=["x"] * 33).status_code == 422
    assert post_embed(client, token_env, texts=["x"] * 32).status_code == 200


def test_embed_truncates_a_long_text_instead_of_rejecting_it(client, token_env):
    FakeVectorizer.reset()
    assert post_embed(client, token_env, texts=["x " * server.MAX_MAIL_CHARS]).status_code == 200
    assert FakeVectorizer.max_len_seen <= server.MAX_MAIL_CHARS


def test_embed_accepts_a_lone_surrogate(client, token_env):
    resp = client.post(
        "/v2/embed", content=b'{"texts": ["a \\ud800 b"], "profile": "campaign"}',
        headers={**token_env, "Content-Type": "application/json"},
    )
    assert resp.status_code == 200, resp.text


def test_embed_503_when_the_vectorizer_is_missing(client, token_env, monkeypatch):
    monkeypatch.setattr(server.store, "vectorizer", None)
    monkeypatch.setattr(server.store, "vectorizer_error", "boom")
    resp = post_embed(client, token_env)
    assert resp.status_code == 503
    assert resp.json() == {"detail": "Vectorizer unavailable: boom"}


def test_campaign_vector_equals_the_classify_campaign_embedding(client, token_env):
    import json
    vector = post_embed(client, token_env, texts=[BODY], profile="campaign").json()["vectors"][0]
    classified = post_v2(client, token_env)
    assert json.loads(classified["campaign_embedding"]) == vector
