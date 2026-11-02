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

import threading  # noqa: E402
import time  # noqa: E402

from inference_server import server, v2  # noqa: E402
from test_inference_server import BODY, FakeVectorizer  # noqa: E402
from test_inference_server_reload import (TokenVectorizer, app, make_bundle,  # noqa: E402,F401
                                          reload, token_env)
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
        held.append(server._inference_slots.free < server.MAX_CONCURRENCY)
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


def test_token_chunking_without_an_encoder_tokenizer_is_422(app, token_env, monkeypatch):
    client = app[0]
    monkeypatch.setattr(server.store, "vectorizer", FakeVectorizer())
    resp = embed(client, token_env, preprocessing="chunkmean-tokens-v1")
    assert resp.status_code == 422
    assert resp.json() == {"detail": "token chunking is not available with this encoder"}
    assert embed(client, token_env, preprocessing="chunkmean-words90-v1").status_code == 200


def test_token_bundle_classify_without_an_encoder_tokenizer_is_422(app, token_env, tmp_path, monkeypatch):
    client, holder, storage, _ = app
    spec, _ = make_bundle(tmp_path, storage)
    assert reload(client, token_env, active=spec).status_code == 200
    monkeypatch.setattr(server.store, "vectorizer", FakeVectorizer())
    resp = client.post("/v2/models/ai_mail/classify", json={"mail_body": BODY}, headers=token_env)
    assert resp.status_code == 422
    assert resp.json() == {"detail": "token chunking is not available with this encoder"}


def test_a_classify_completes_while_a_32_text_embed_runs(app, token_env):
    """One free inference slot: the embed takes it per text, so a classify gets in between texts
    instead of waiting for all 32."""
    client = app[0]
    taken = server.MAX_CONCURRENCY - 1
    for _ in range(taken):
        server._inference_slots.acquire()
    TokenVectorizer.delay = 0.02
    done = {}
    try:
        def run_embed():
            r = embed(client, token_env, texts=[f"{TEXT} {i}" for i in range(32)],
                      preprocessing="chunkmean-tokens-v1")
            done["embed"] = (time.monotonic(), r.status_code)

        worker = threading.Thread(target=run_embed)
        worker.start()
        while not TokenVectorizer.batches:
            time.sleep(0.005)
        r = client.post("/v2/models/ai_mail/classify", json={"mail_body": BODY}, headers=token_env)
        done["classify"] = (time.monotonic(), r.status_code)
        worker.join()
    finally:
        TokenVectorizer.delay = 0.0
        for _ in range(taken):
            server._inference_slots.release()
    assert done["classify"][1] == 200 and done["embed"][1] == 200
    assert done["classify"][0] < done["embed"][0]


def test_fair_semaphore_serves_a_waiter_before_a_releaser_that_asks_again():
    sem, order = server.FairSemaphore(1), []
    sem.acquire()

    def waiter():
        with sem:
            order.append("waiter")

    t = threading.Thread(target=waiter)
    t.start()
    while not sem._queue:
        time.sleep(0.001)
    sem.release()
    with sem:
        order.append("releaser")
    t.join()
    assert order == ["waiter", "releaser"]
    with pytest.raises(ValueError):
        sem.release()


def test_fair_semaphore_drops_a_waiter_whose_wait_raises():
    sem, raised = server.FairSemaphore(1), []
    sem.acquire()
    real_wait = sem._cond.wait

    def wait_once(*a, **k):
        sem._cond.wait = real_wait
        raise KeyboardInterrupt  # any BaseException

    sem._cond.wait = wait_once

    def waiter():
        try:
            sem.acquire()
        except KeyboardInterrupt:
            raised.append(True)

    t = threading.Thread(target=waiter, daemon=True)
    t.start()
    t.join(2)
    assert raised == [True] and not sem._queue
    sem.release()
    got = []
    t2 = threading.Thread(target=lambda: (sem.acquire(), got.append(True)), daemon=True)
    t2.start()
    t2.join(2)
    assert got == [True] and not sem._queue


@pytest.mark.parametrize("route,body", [
    ("/v2/embed", b'{"texts": ' + b"[" * 100000 + b"]" * 100000 + b', "profile": "campaign"}'),
    ("/v2/models/ai_mail/classify", b'{"mail_body": ' + b"[" * 100000 + b"]" * 100000 + b"}"),
])
def test_deeply_nested_json_is_a_422_without_echo(app, token_env, route, body):
    resp = app[0].post(route, content=body, headers={**token_env, "Content-Type": "application/json"})
    assert resp.status_code == 422
    assert resp.json() == {"detail": [{"loc": [], "msg": "Invalid JSON"}]}
