"""
POST /v2/embed with a chosen preprocessing (Plan E, Task 8a): the label ledger embeds its rows in
the form the retrain recipe trains on. Uses the reload tests' app fixture (real server, encoder
faked with a word tokenizer so token chunking runs).
"""
import numpy as np
import pytest

pytest.importorskip("torch")
pytest.importorskip("sentence_transformers")
pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from inference_server import server, v2  # noqa: E402
from test_inference_server_reload import TokenVectorizer, app, token_env  # noqa: E402,F401
from training import recipe  # noqa: E402

TEXT = " ".join(f"w{i}" for i in range(40))  # several chunks of the fake 12-token window


def embed(client, headers, texts=(TEXT,), profile="classifier", **extra):
    return client.post("/v2/embed", json={"texts": list(texts), "profile": profile, **extra},
                       headers=headers)


def test_default_is_legacy_first128_and_unchanged(app, token_env):
    client = app[0]
    default = embed(client, token_env).json()
    explicit = embed(client, token_env, preprocessing="legacy-first128").json()
    assert default == explicit
    assert default["preprocessing_version"] == "legacy-first128"
    plain = np.asarray(TokenVectorizer().encode([TEXT]), dtype=np.float32)[0]
    assert default["vectors"][0] == [float(x) for x in plain]


@pytest.mark.parametrize("pv,by_tokens", [("chunkmean-tokens-v1", True),
                                          ("chunkmean-words90-v1", False)])
def test_chunked_forms_use_chunk_mean_embedding(app, token_env, pv, by_tokens):
    client = app[0]
    body = embed(client, token_env, texts=[TEXT, "short"], preprocessing=pv).json()
    assert body["preprocessing_version"] == pv
    assert body["embedding_version"] == "cmp-e1"
    vec = TokenVectorizer()
    for text, got in zip([TEXT, "short"], body["vectors"]):
        want = recipe.chunk_mean_embedding(vec, text, by_tokens=by_tokens)
        assert got == [float(x) for x in want]


def test_campaign_profile_always_uses_first128(app, token_env):
    client = app[0]
    legacy = embed(client, token_env, profile="campaign").json()
    for pv in ("chunkmean-tokens-v1", "chunkmean-words90-v1"):
        body = embed(client, token_env, profile="campaign", preprocessing=pv).json()
        assert body["vectors"] == legacy["vectors"]
        assert body["preprocessing_version"] == "legacy-first128"


def test_unknown_preprocessing_is_422_with_loc_and_msg_only(app, token_env):
    resp = embed(app[0], token_env, preprocessing="chunkmean-v9")
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert all(set(d) == {"loc", "msg"} for d in detail)
    assert "chunkmean-v9" not in resp.text and TEXT not in resp.text


def test_chunked_embedding_runs_inside_the_inference_semaphore(app, token_env, monkeypatch):
    held = []
    real = v2.chunk_mean_embedding

    def spy(*args, **kwargs):
        held.append(server._inference_slots._value < server.MAX_CONCURRENCY)
        return real(*args, **kwargs)

    monkeypatch.setattr(v2, "chunk_mean_embedding", spy)
    assert embed(app[0], token_env, texts=["a", "b"],
                 preprocessing="chunkmean-tokens-v1").status_code == 200
    assert held == [True, True]


def test_caps_still_apply_with_a_preprocessing(app, token_env):
    client = app[0]
    assert embed(client, token_env, texts=["x"] * 33,
                 preprocessing="chunkmean-tokens-v1").status_code == 422
    big = "x" * (v2.MAX_CLASSIFY_BODY + 1)
    assert embed(client, token_env, texts=[big],
                 preprocessing="chunkmean-tokens-v1").status_code == 413
