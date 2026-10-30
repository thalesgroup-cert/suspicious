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
from test_inference_server import FakeVectorizer, write_models  # noqa: E402

TOKEN = "s3cret-test-token"


@pytest.fixture
def make_client(tmp_path, monkeypatch):
    """Factory: the real server.app (legacy + v2 routes) against temp model dirs."""
    clients = []

    def make(personal=True):
        dirs = {"personal": tmp_path / "models", "public": tmp_path / "models_public"}
        for directory in dirs.values():
            directory.mkdir()
        if personal:
            write_models(dirs["personal"], seed=1)
        monkeypatch.setattr(server, "MODEL_DIRS", dirs)
        # The v2 router captured server.store at import time, so (unlike the legacy
        # tests, which swap the module attribute) reset that same object in place.
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
