"""
Tests for POST /v2/reload and bundle-aware classify (Plan E, Task 6b): inference_server/bundles.py
and its wiring in v2.py / server.py. Bundles are written with training.bundle.write_bundle and
served by an httpx.MockTransport; the encoder is a deterministic fake with a word tokenizer.
"""
import hashlib
import io
import json
import logging
import os
import threading
import time

import numpy as np
import pytest

torch = pytest.importorskip("torch")
pytest.importorskip("sentence_transformers")
pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from inference_server import bundles, server, training_job  # noqa: E402
from mail_analysis import MODEL_SPECS  # noqa: E402
from ResNetMLP import ResNetMLP  # noqa: E402
from test_inference_server import BODY, FakeVectorizer, write_models  # noqa: E402
from training import recipe  # noqa: E402
from training.bundle import BUNDLE_FILES, write_bundle  # noqa: E402
from training.recipe import HEADS, NUM_OUT, Heads, Knn  # noqa: E402

TOKEN = "s3cret-test-token"
HOST = "rustfs:9000"
SECRET = "X-Amz-Signature=deadbeefsecret"
NAMES = (*BUNDLE_FILES, "manifest.json")
DIM = 768
LEGACY_FILES = {"safe_suspicious": "safe_suspicious_30_epochs_model.pth",
                "spam_dangerous": "spam_dangerous_30_epochs_model.pth",
                "safe": "safe_30_epochs_model.pth", "unwanted": "unwanted_30_epochs_model.pth",
                "dangerous": "dangerous_30_epochs_model.pth"}


class WordTokenizer:
    def encode(self, text, add_special_tokens=True):
        return [7] * len(text.split()) + ([0, 2] if add_special_tokens else [])


class TokenVectorizer(FakeVectorizer):
    """FakeVectorizer plus the tokenizer interface chunk_by_tokens needs; records each batch."""
    max_seq_length = 12
    tokenizer = WordTokenizer()
    batches = []
    progress_flags = []

    def encode(self, texts, show_progress_bar=None):
        TokenVectorizer.batches.append(list(texts))
        TokenVectorizer.progress_flags.append(show_progress_bar)
        return super().encode(texts)


# --- fixtures ----------------------------------------------------------------------------------


@pytest.fixture
def token_env(monkeypatch):
    monkeypatch.setenv("AI_INFERENCE_TOKEN", TOKEN)
    monkeypatch.setenv("AI_BUNDLE_HOSTS", HOST)
    return {"Authorization": f"Bearer {TOKEN}"}


class Store:
    """MockTransport handler serving bundles by URL."""

    def __init__(self):
        self.files = {}
        self.requests = []
        self.override = None

    def __call__(self, request):
        self.requests.append(request)
        if self.override:
            return self.override(request)
        data = self.files.get(str(request.url))
        if data is None:
            return httpx.Response(404)
        return httpx.Response(200, headers={"Content-Length": str(len(data))},
                              stream=httpx.ByteStream(data))


@pytest.fixture
def app(tmp_path, monkeypatch, token_env):
    """(client, holder, storage, base): the real server app, a fresh holder, temp model dirs."""
    dirs = {"personal": tmp_path / "models"}
    write_models(dirs["personal"], seed=1)
    monkeypatch.setattr(server, "MODEL_DIRS", dirs)
    monkeypatch.setattr(server.store, "__dict__", server.ModelStore(dirs).__dict__)
    monkeypatch.setattr(server, "SentenceTransformer", TokenVectorizer)
    monkeypatch.setattr(server, "RELOAD_CHECK_SECONDS", 0)
    TokenVectorizer.reset()
    TokenVectorizer.batches = []
    storage = Store()
    base = tmp_path / "reload-tmp"
    base.mkdir()
    holder = bundles.ModelHolder(transport=httpx.MockTransport(storage), tmp_base=str(base))
    monkeypatch.setattr(server.holder, "__dict__", holder.__dict__)
    monkeypatch.setattr(server, "VECTORIZER_PATH", str(tmp_path / "no-encoder-files"))
    client = TestClient(server.app)
    client.__enter__()
    server.store._encoder_hash = "h"  # make_bundle's manifests say "h"
    yield client, server.holder, storage, base
    client.__exit__(None, None, None)


def make_bundle(tmp_path, storage, *, version="v-1", preprocessing="chunkmean-tokens-v1",
                dim=DIM, heads=None, knn=None, manifest_extra=None, name=None):
    """Write a bundle, serve it, return the reload spec."""
    if heads is None:
        torch.manual_seed(3)
        heads = Heads({h: ResNetMLP(dim, NUM_OUT[h]).eval() for h in HEADS}, dim)
    if knn is None:
        rng = np.random.default_rng(4)
        knn = Knn(rng.normal(size=(30, dim)).astype(np.float32), np.arange(30) % 3,
                  np.arange(100, 130, dtype=np.int64))
    manifest = {"version_id": version, "recipe_id": "candidate-v1",
                "preprocessing_version": preprocessing, "encoder_id": "enc", "encoder_hash": "h",
                "ledger_digest": "l", "campaign_refs_digest": "c", "metrics": {}, "gate": {},
                "parent_version": None, "trainer_revision": "t", **(manifest_extra or {})}
    out = tmp_path / (name or f"bundle-{version}")
    sha = write_bundle(out, heads=heads, knn=knn, campaign_profile={"distance_threshold": 0.25},
                       calibration={"temperature": {"hierarchy": 1.7, "knn": 1.3},
                                    "tier_cutoffs": {"high": 0.9, "medium": 0.6},
                                    "held_out_groups": {}},
                       manifest=manifest)
    urls = {}
    for n in NAMES:
        url = f"http://{HOST}/models/{version}/{n}?{SECRET}"
        storage.files[url] = (out / n).read_bytes()
        urls[n] = url
    return {"version_id": version, "bundle_urls": urls, "manifest_sha256": sha}, out


def legacy_heads(models_dir):
    models = {}
    for h, f in LEGACY_FILES.items():
        m = ResNetMLP(DIM, NUM_OUT[h])
        m.load_state_dict(torch.load(models_dir / f, weights_only=True))
        models[h] = m.eval()
    return Heads(models, DIM)


def reload(client, headers, active=None, shadow=None):
    return client.post("/v2/reload", json={"active": active, "shadow": shadow}, headers=headers)


def classify(client, headers, body=BODY, **extra):
    r = client.post("/v2/models/ai_mail/classify", json={"mail_body": body, **extra},
                    headers=headers)
    assert r.status_code == 200, r.text
    return r.json()


def expected(holder_model, vectorizer, body, by_tokens=True, exclude=None):
    x = recipe.chunk_mean_embedding(vectorizer, body, by_tokens=by_tokens)
    p = recipe.predict(holder_model.heads, holder_model.knn, x[None],
                       temperature=holder_model.calibration["temperature"],
                       exclude_case_ids=exclude)
    return p


# --- auth and request rules --------------------------------------------------------------------


def test_reload_requires_the_token(app, token_env):
    client, *_ = app
    assert client.post("/v2/reload", json={"active": None, "shadow": None}).status_code == 401


@pytest.mark.parametrize("payload", [
    {"active": None},
    {"active": None, "shadow": None, "extra": 1},
    {"active": {"version_id": "v", "bundle_urls": {}, "manifest_sha256": "0" * 64},
     "shadow": None},
    {"active": {"version_id": "../v", "bundle_urls": {n: f"http://{HOST}/x?{SECRET}" for n in NAMES},
                "manifest_sha256": "0" * 64}, "shadow": None},
    {"active": {"version_id": "v", "bundle_urls": {n: f"http://{HOST}/x?{SECRET}" for n in NAMES},
                "manifest_sha256": "A" * 64}, "shadow": None},
])
def test_reload_body_is_strict(app, token_env, payload):
    client, holder, storage, _ = app
    r = client.post("/v2/reload", json=payload, headers=token_env)
    assert r.status_code == 422 and SECRET not in r.text and HOST not in r.text
    assert not storage.requests


def test_reload_body_is_capped(app, token_env):
    client, *_ = app
    r = client.post("/v2/reload", content=b'{"active": null, "shadow": null, "x": "' + b"x" * 70000
                    + b'"}', headers={**token_env, "Content-Type": "application/json"})
    assert r.status_code == 413


# --- loading a bundle --------------------------------------------------------------------------


def test_good_token_bundle_becomes_active_and_classify_uses_it(app, token_env, tmp_path):
    client, holder, storage, base = app
    spec, _ = make_bundle(tmp_path, storage)
    r = reload(client, token_env, active=spec)
    assert r.status_code == 200, r.text
    assert r.json()["active"]["id"] == "v-1"
    meta = client.get("/v2/models/ai_mail", headers=token_env).json()
    assert meta["versions"]["active"]["id"] == "v-1"
    assert meta["versions"]["active"]["preprocessing"] == "chunkmean-tokens-v1"
    assert meta["versions"]["active"]["manifest_sha256"] == spec["manifest_sha256"]
    assert not os.listdir(base)

    body = " ".join(f"word{i}" for i in range(50))  # 50 words, 10 per chunk: 5 chunks
    TokenVectorizer.batches = []
    out = classify(client, token_env, body)
    batches = sorted(len(b) for b in TokenVectorizer.batches)
    res = out["results"]["active"]
    assert res["version"] == "v-1" and res["tier"] is None
    vec = server.store.vectorizer
    p = expected(holder.state[0], vec, body)
    main = p.main[0]
    assert res["probabilities"] == {"SAFE": float(main[0]), "UNWANTED": float(main[1]),
                                    "DANGEROUS": float(main[2])}
    sub = np.concatenate([p.sub["safe"][0] * main[0], p.sub["unwanted"][0] * main[1],
                          p.sub["dangerous"][0] * main[2]])
    assert list(res["sub_probabilities"].values()) == [float(v) for v in sub]
    assert res["class"] in ("SAFE", "UNWANTED", "DANGEROUS", "INCONCLUSIVE")
    # campaign embedding: the plain first-128 encode (cmp-e1), unchanged
    assert out["campaign_embedding"] == str(vec.encode([body]).tolist()[0])
    assert out["campaign_embedding_version"] == "cmp-e1"
    assert batches == [1, 5]  # one batch of 5 chunks plus the campaign pass


def test_bundle_classify_never_draws_a_progress_bar(app, token_env, tmp_path):
    client, holder, storage, _ = app
    spec, _ = make_bundle(tmp_path, storage)
    assert reload(client, token_env, active=spec).status_code == 200
    TokenVectorizer.progress_flags = []
    classify(client, token_env, " ".join(["w"] * 40))
    assert TokenVectorizer.progress_flags and set(TokenVectorizer.progress_flags) == {False}


def test_words90_bundle_uses_word_chunks(app, token_env, tmp_path):
    client, holder, storage, _ = app
    spec, _ = make_bundle(tmp_path, storage, preprocessing="chunkmean-words90-v1")
    assert reload(client, token_env, active=spec).status_code == 200
    body = " ".join(f"w{i}" for i in range(200))  # 90-word chunks: 3
    TokenVectorizer.batches = []
    res = classify(client, token_env, body)["results"]["active"]
    assert sorted(len(b) for b in TokenVectorizer.batches) == [1, 3]
    p = expected(holder.state[0], server.store.vectorizer, body, by_tokens=False)
    assert res["probabilities"]["DANGEROUS"] == float(p.main[0][2])


def test_exclude_case_ids_leaves_the_case_out_of_the_vote(app, token_env, tmp_path):
    client, holder, storage, _ = app
    body = "an exact copy of a labelled mail"
    vec = server.store.vectorizer
    x = recipe.chunk_mean_embedding(vec, body)
    rng = np.random.default_rng(5)
    emb = np.vstack([x[None], rng.normal(size=(9, DIM))]).astype(np.float32)
    knn = Knn(emb, np.array([2] + [0] * 9), np.arange(500, 510, dtype=np.int64))
    spec, _ = make_bundle(tmp_path, storage, knn=knn)
    assert reload(client, token_env, active=spec).status_code == 200
    with_self = classify(client, token_env, body)["results"]["active"]["probabilities"]
    without = classify(client, token_env, body, exclude_case_ids=[500])["results"]["active"]
    model = holder.state[0]
    assert with_self["DANGEROUS"] == float(expected(model, vec, body).main[0][2])
    assert without["probabilities"]["DANGEROUS"] == float(
        expected(model, vec, body, exclude=[500]).main[0][2])
    assert without["probabilities"]["DANGEROUS"] < with_self["DANGEROUS"]


@pytest.mark.parametrize("ids", [["1"], [True], [1.0], list(range(1001)), [2**63], [-1]])
def test_exclude_case_ids_are_strict(app, token_env, ids):
    client, *_ = app
    r = client.post("/v2/models/ai_mail/classify",
                    json={"mail_body": BODY, "exclude_case_ids": ids}, headers=token_env)
    assert r.status_code == 422


def test_every_neighbour_excluded_is_422(app, token_env, tmp_path):
    client, holder, storage, _ = app
    knn = Knn(np.ones((2, DIM), np.float32), np.array([0, 1]), np.array([1, 2], dtype=np.int64))
    spec, _ = make_bundle(tmp_path, storage, knn=knn)
    assert reload(client, token_env, active=spec).status_code == 200
    r = client.post("/v2/models/ai_mail/classify",
                    json={"mail_body": BODY, "exclude_case_ids": [1, 2]}, headers=token_env)
    assert r.status_code == 422


# --- legacy behaviour ---------------------------------------------------------------------------


def _strip(answer):
    answer = json.loads(json.dumps(answer))
    answer.pop("latency_ms")
    answer["results"]["active"].pop("version")
    return answer


def test_no_bundle_is_todays_legacy_answer(app, token_env):
    client, *_ = app
    out = classify(client, token_env)
    legacy = server._classify(server.store.models("personal"), BODY)
    assert out["results"]["active"]["version"] == "v0"
    assert out["results"]["active"]["probabilities"] == legacy["classification_breakdown"]
    assert out["results"]["active"]["contributing_phrases"] == legacy["contributing_phrases"]


def test_legacy_first128_bundle_answers_exactly_like_v0(app, token_env, tmp_path):
    client, holder, storage, _ = app
    before = classify(client, token_env, exclude_case_ids=[1])
    spec, _ = make_bundle(tmp_path, storage, version="v0-import", preprocessing="legacy-first128",
                          heads=legacy_heads(tmp_path / "models"))
    assert reload(client, token_env, active=spec).status_code == 200
    after = classify(client, token_env, exclude_case_ids=[1])
    assert after["results"]["active"]["version"] == "v0-import"
    assert _strip(after) == _strip(before)


def test_active_null_rolls_back_to_the_legacy_weights(app, token_env, tmp_path):
    client, holder, storage, _ = app
    before = classify(client, token_env)
    spec, _ = make_bundle(tmp_path, storage)
    assert reload(client, token_env, active=spec).status_code == 200
    assert classify(client, token_env)["results"]["active"]["version"] == "v-1"
    r = reload(client, token_env, active=None)
    assert r.status_code == 200 and r.json()["active"]["id"] == "v0"
    after = classify(client, token_env)
    assert after["results"]["active"]["version"] == "v0" and _strip(after) == _strip(before)
    assert client.get("/v2/models/ai_mail", headers=token_env).json()["versions"]["active"][
        "preprocessing"] == "legacy-first128"


# --- refusals leave the old model active ------------------------------------------------------


def _assert_refused_keeps(client, token_env, r, base, version):
    assert r.status_code == 422, r.text
    assert SECRET not in r.text and HOST not in r.text and "http" not in r.text
    assert classify(client, token_env)["results"]["active"]["version"] == version
    assert not os.listdir(base)


@pytest.fixture
def loaded(app, token_env, tmp_path):
    client, holder, storage, base = app
    spec, _ = make_bundle(tmp_path, storage, version="v-old", name="old")
    assert reload(client, token_env, active=spec).status_code == 200
    return app


def test_hash_mismatch_is_refused(loaded, token_env, tmp_path):
    client, holder, storage, base = loaded
    spec, _ = make_bundle(tmp_path, storage, version="v-new")
    spec["manifest_sha256"] = "0" * 64
    _assert_refused_keeps(client, token_env, reload(client, token_env, active=spec), base, "v-old")


def test_corrupt_bundle_is_refused(loaded, token_env, tmp_path):
    client, holder, storage, base = loaded
    spec, _ = make_bundle(tmp_path, storage, version="v-new")
    url = spec["bundle_urls"]["heads/safe.npz"]
    data = bytearray(storage.files[url])
    data[-100] ^= 1
    storage.files[url] = bytes(data)
    r = reload(client, token_env, active=spec)
    _assert_refused_keeps(client, token_env, r, base, "v-old")
    assert "heads/safe.npz" in r.text


@pytest.mark.parametrize("kw, why", [
    ({"preprocessing": "chunkmean-sentences-v9"}, "preprocessing"),
    ({"dim": 16}, "input_dim"),
    ({"version": "v-other"}, "version"),
    ({"manifest_extra": {"encoder_hash": "e" * 64}}, "another encoder"),
])
def test_bundle_the_server_cannot_serve_is_refused(loaded, token_env, tmp_path, kw, why):
    client, holder, storage, base = loaded
    spec, _ = make_bundle(tmp_path, storage, **kw)
    if why == "version":
        spec["version_id"] = "v-new"
    r = reload(client, token_env, active=spec)
    _assert_refused_keeps(client, token_env, r, base, "v-old")
    assert why in r.text


def test_a_bundle_without_an_encoder_hash_still_loads(app, token_env, tmp_path):
    client, holder, storage, base = app
    spec, _ = make_bundle(tmp_path, storage, version="v-nohash", manifest_extra={"encoder_hash": ""})
    assert reload(client, token_env, active=spec).status_code == 200


def test_missing_encoder_is_refused(loaded, token_env, tmp_path, monkeypatch):
    client, holder, storage, base = loaded
    spec, _ = make_bundle(tmp_path, storage, version="v-new")
    monkeypatch.setattr(server.store, "vectorizer", None)
    r = reload(client, token_env, active=spec)
    assert r.status_code == 422 and "encoder" in r.text
    assert holder.state[0].version_id == "v-old" and not os.listdir(base)


def test_token_bundle_needs_an_encoder_tokenizer(loaded, token_env, tmp_path, monkeypatch):
    client, holder, storage, base = loaded
    spec, _ = make_bundle(tmp_path, storage, version="v-new")
    monkeypatch.setattr(server.store, "vectorizer", FakeVectorizer())
    r = reload(client, token_env, active=spec)
    assert r.status_code == 422 and "tokenizer" in r.text
    assert holder.state[0].version_id == "v-old"


def test_a_bad_shadow_refuses_the_whole_reload(loaded, token_env, tmp_path):
    client, holder, storage, base = loaded
    good, _ = make_bundle(tmp_path, storage, version="v-new")
    bad, _ = make_bundle(tmp_path, storage, version="v-bad", dim=16)
    r = reload(client, token_env, active=good, shadow=bad)
    _assert_refused_keeps(client, token_env, r, base, "v-old")
    assert "shadow" in r.text


@pytest.mark.parametrize("respond, why", [
    (lambda r: httpx.Response(302, headers={"Location": "http://evil/"}), "redirect"),
    (lambda r: httpx.Response(200, stream=httpx.ByteStream(b"x")), "content length"),
    (lambda r: httpx.Response(200, headers={"Content-Length": str(60 * 2**20)},
                              stream=httpx.ByteStream(b"x")), "cap"),
    (lambda r: httpx.Response(200, headers={"Content-Length": "10", "Content-Encoding": "gzip"},
                              stream=httpx.ByteStream(b"x" * 10)), "encoding"),
])
def test_download_rules_apply_to_reload(loaded, token_env, tmp_path, respond, why):
    client, holder, storage, base = loaded
    spec, _ = make_bundle(tmp_path, storage, version="v-new")
    storage.override = respond
    n = len(storage.requests)
    r = reload(client, token_env, active=spec)
    storage.override = None
    _assert_refused_keeps(client, token_env, r, base, "v-old")
    assert why in r.text
    assert len(storage.requests) == n + 1  # stopped at the first file, no redirect followed


def test_json_file_caps_apply_before_the_write(loaded, token_env, tmp_path):
    client, holder, storage, base = loaded
    spec, _ = make_bundle(tmp_path, storage, version="v-new")
    url = spec["bundle_urls"]["calibration.json"]
    storage.files[url] = b" " * (64 * 1024 + 1)
    r = reload(client, token_env, active=spec)
    _assert_refused_keeps(client, token_env, r, base, "v-old")
    assert "cap" in r.text


@pytest.mark.parametrize("url", [
    f"http://evil:9000/x?{SECRET}", f"ftp://{HOST}/x?{SECRET}", f"http://u:p@{HOST}/x?{SECRET}",
    f"http://{HOST}#@evil/x",
])
def test_url_rules_apply_to_reload(loaded, token_env, tmp_path, url):
    client, holder, storage, base = loaded
    spec, _ = make_bundle(tmp_path, storage, version="v-new")
    spec["bundle_urls"]["knn_index.npz"] = url
    n = len(storage.requests)
    r = reload(client, token_env, active=spec)
    _assert_refused_keeps(client, token_env, r, base, "v-old")
    assert len(storage.requests) == n  # refused before any download


def test_one_reload_at_a_time(loaded, token_env, tmp_path):
    client, holder, storage, base = loaded
    spec, _ = make_bundle(tmp_path, storage, version="v-new")
    assert holder._reload_lock.acquire(blocking=False)
    try:
        assert reload(client, token_env, active=spec).status_code == 409
    finally:
        holder._reload_lock.release()
    assert reload(client, token_env, active=spec).status_code == 200


def test_reload_sweeps_its_own_leftovers(loaded, token_env, tmp_path):
    client, holder, storage, base = loaded
    (base / "ai-reload-crashed").mkdir()
    (base / "other").mkdir()
    spec, _ = make_bundle(tmp_path, storage, version="v-new")
    assert reload(client, token_env, active=spec).status_code == 200
    assert os.listdir(base) == ["other"]


def test_files_are_written_under_fixed_names_in_a_private_dir(loaded, token_env, tmp_path,
                                                              monkeypatch):
    client, holder, storage, base = loaded
    spec, _ = make_bundle(tmp_path, storage, version="v-new")
    seen = {}
    real = bundles.read_bundle

    def spy(d, **kw):
        seen["mode"] = os.stat(d).st_mode & 0o777
        seen["files"] = sorted(os.path.relpath(os.path.join(r, f), d)
                               for r, _, fs in os.walk(d) for f in fs)
        seen["file_modes"] = {os.stat(os.path.join(d, f)).st_mode & 0o777 for f in seen["files"]}
        return real(d, **kw)

    monkeypatch.setattr(bundles, "read_bundle", spy)
    assert reload(client, token_env, active=spec).status_code == 200
    assert seen["mode"] == 0o700 and seen["files"] == sorted(NAMES)
    assert seen["file_modes"] == {0o600}


# --- swap semantics -----------------------------------------------------------------------------


def test_in_flight_classify_finishes_on_the_old_model(loaded, token_env, tmp_path):
    client, holder, storage, base = loaded
    spec, _ = make_bundle(tmp_path, storage, version="v-new")
    result = {}
    started = threading.Event()
    real = bundles.classify_bundle

    def slow(model, *a, **k):
        started.set()
        time.sleep(1.0)
        return real(model, *a, **k)

    bundles.classify_bundle = slow
    try:
        t = threading.Thread(target=lambda: result.update(classify(client, token_env)))
        t.start()
        assert started.wait(10)
        assert reload(client, token_env, active=spec).status_code == 200
        t.join(30)
    finally:
        bundles.classify_bundle = real
    assert result["results"]["active"]["version"] == "v-old"
    assert classify(client, token_env)["results"]["active"]["version"] == "v-new"


def test_shadow_is_stored_but_not_used(loaded, token_env, tmp_path):
    client, holder, storage, base = loaded
    old = holder.state[0]
    spec, _ = make_bundle(tmp_path, storage, version="v-shadow")
    r = reload(client, token_env, active={"version_id": old.version_id, "bundle_urls": {},
                                          "manifest_sha256": old.manifest_sha256})
    assert r.status_code == 422  # active must be fully specified
    active, _ = make_bundle(tmp_path, storage, version="v-act")
    assert reload(client, token_env, active=active, shadow=spec).status_code == 200
    meta = client.get("/v2/models/ai_mail", headers=token_env).json()["versions"]
    assert meta["active"]["id"] == "v-act" and meta["shadow"]["id"] == "v-shadow"
    assert classify(client, token_env)["results"]["active"]["version"] == "v-act"
    assert client.post("/v2/models/ai_mail/classify",
                       json={"mail_body": BODY, "versions": ["shadow"]},
                       headers=token_env).status_code == 400


def test_reload_logs_carry_no_presigned_url(app, token_env, tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    client, holder, storage, base = app
    spec, _ = make_bundle(tmp_path, storage)
    reload(client, token_env, active=spec)
    spec["manifest_sha256"] = "0" * 64
    reload(client, token_env, active=spec)
    text = caplog.text + "".join(r.getMessage() for r in caplog.records)
    assert "deadbeef" not in text and "X-Amz-Signature=" not in text


def test_knn_vote_exclusion_unit():
    knn = Knn(np.eye(4, dtype=np.float32), np.array([0, 1, 2, 2]),
              np.array([10, 11, 12, 13], dtype=np.int64))
    x = np.eye(4, dtype=np.float32)[:1]
    assert knn.vote(x)[0].tolist() == [1.0, 0.0, 0.0]  # exact match takes the vote
    v = knn.vote(x, exclude_case_ids=[10])
    assert v[0, 0] == 0.0 and abs(v[0].sum() - 1) < 1e-9
    with pytest.raises(ValueError):
        knn.vote(x, exclude_case_ids=[10, 11, 12, 13])
    no_ids = Knn(np.eye(4, dtype=np.float32), np.array([0, 1, 2, 2]))
    assert no_ids.vote(x, exclude_case_ids=[10]).tolist() == knn.vote(x).tolist()


# --- fix wave (review of Task 6b) ------------------------------------------------------------


def test_calibrated_only_where_temperatures_apply(app, token_env, tmp_path):
    client, holder, storage, _ = app
    meta = lambda: client.get("/v2/models/ai_mail", headers=token_env).json()["versions"]  # noqa
    assert meta()["active"]["calibrated"] is False  # active null: legacy weights
    spec, _ = make_bundle(tmp_path, storage, version="v0-import", preprocessing="legacy-first128",
                          heads=legacy_heads(tmp_path / "models"))
    assert reload(client, token_env, active=spec).json()["active"]["calibrated"] is False
    assert meta()["active"]["calibrated"] is False
    spec, _ = make_bundle(tmp_path, storage, version="v-cm")
    assert reload(client, token_env, active=spec).json()["active"]["calibrated"] is True


@pytest.mark.parametrize("path, payload", [
    ("/v2/models/ai_mail/classify", {"mail_body": BODY, "exclude_case_ids": [True]}),
    ("/v2/models/ai_mail/classify", {"mail_body": BODY, "exclude_case_ids": ["SECRETVALUE"]}),
    ("/v2/models/ai_mail/classify", {"mail_body": "SECRETVALUE " * 3,
                                     "exclude_case_ids": list(range(1001))}),
    ("/v2/models/ai_mail/classify", {"mail_body": {"x": "SECRETVALUE"}}),
    ("/v2/models/ai_mail/classify", {"mail_body": 12345678}),
    ("/v2/embed", {"texts": ["SECRETVALUE"], "profile": "SECRETVALUE"}),
    ("/v2/embed", {"texts": ["SECRETVALUE"] * 33, "profile": "classifier"}),
])
def test_validation_errors_never_echo_the_request(app, token_env, path, payload):
    client, *_ = app
    r = client.post(path, json=payload, headers=token_env)
    assert r.status_code == 422
    assert "SECRETVALUE" not in r.text and "12345678" not in r.text
    for err in r.json()["detail"]:
        assert set(err) == {"loc", "msg"}


def test_classify_body_cap_is_large_but_bounded(app, token_env, monkeypatch):
    client, *_ = app
    from inference_server import v2
    assert v2.MAX_CLASSIFY_BODY >= 16 * server.MAX_MAIL_CHARS
    monkeypatch.setattr(v2, "MAX_CLASSIFY_BODY", 1000)
    r = client.post("/v2/models/ai_mail/classify", json={"mail_body": "x" * 2000},
                    headers=token_env)
    assert r.status_code == 413


def test_no_neighbours_is_its_own_error():
    knn = Knn(np.ones((1, 4), np.float32), np.array([0]), np.array([5], dtype=np.int64))
    with pytest.raises(recipe.NoNeighbours):
        knn.vote(np.ones((1, 4), np.float32), exclude_case_ids=[5])
    assert issubclass(recipe.NoNeighbours, ValueError)


def test_other_classify_errors_are_a_generic_500(app, token_env, tmp_path, monkeypatch, caplog):
    client, holder, storage, _ = app
    spec, _ = make_bundle(tmp_path, storage)
    assert reload(client, token_env, active=spec).status_code == 200

    def boom(*a, **k):
        raise ValueError("SECRETVALUE in a message")

    monkeypatch.setattr(bundles, "classify_bundle", boom)
    r = client.post("/v2/models/ai_mail/classify", json={"mail_body": BODY}, headers=token_env)
    assert r.status_code == 500 and "SECRETVALUE" not in r.text
    assert "ValueError" in caplog.text and "SECRETVALUE" not in caplog.text


def test_reload_time_limit_env_falls_back_on_a_bad_value(app, token_env, tmp_path, monkeypatch):
    client, holder, storage, _ = app
    monkeypatch.setenv("AI_RELOAD_MAX_SECONDS", "not-a-number")
    spec, _ = make_bundle(tmp_path, storage)
    assert reload(client, token_env, active=spec).status_code == 200


def test_unexpected_reload_error_is_a_generic_500(loaded, token_env, tmp_path, monkeypatch,
                                                  caplog):
    client, holder, storage, base = loaded
    spec, _ = make_bundle(tmp_path, storage, version="v-new")

    def boom(*a, **k):
        raise RuntimeError("SECRETVALUE")

    monkeypatch.setattr(bundles, "read_bundle", boom)
    r = reload(client, token_env, active=spec)
    assert r.status_code == 500 and "SECRETVALUE" not in r.text
    assert "RuntimeError" in caplog.text and "SECRETVALUE" not in caplog.text
    assert holder.state[0].version_id == "v-old" and not os.listdir(base)
