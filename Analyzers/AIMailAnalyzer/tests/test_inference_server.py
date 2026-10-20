"""
Tests for inference_server/server.py.

The app under test is the real FastAPI app and the real ResNetMLP/torch code
path: weights are random-init checkpoints written to a temp dir with
torch.save and loaded back through the server's own loader (weights_only=True,
shape checks and all). Only the sentence-transformer is faked - it is a
~1 GB download and the classifier heads are what this module is responsible
for - plus one skipped-unless-present smoke test against the real vectorizer.

Needs the inference stack (pip install -r requirements-inference.txt httpx
pytest); skipped cleanly where torch / sentence_transformers / fastapi are
missing, e.g. in the thin-client venv.
"""
import hashlib
import json
import threading
import time
from pathlib import Path

import numpy as np
import pytest

torch = pytest.importorskip("torch")
pytest.importorskip("sentence_transformers")
pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

import mail_analysis  # noqa: E402
from inference_server import server  # noqa: E402
from mail_analysis import MODEL_SPECS  # noqa: E402
from ResNetMLP import ResNetMLP  # noqa: E402

DIM = 768
VECTORIZER_DIR = (
    Path(__file__).resolve().parent.parent / "vectorizers" / "paraphrase-multilingual-mpnet-base-v2"
)
BODY = (
    "Dear customer. Your account has been suspended. "
    "Click the link below to verify your password immediately! "
    "Failure to act will close your account."
)


class FakeVectorizer:
    """Deterministic stand-in for SentenceTransformer: same text -> same 768-d
    vector. Class-level counters let tests observe how it is driven."""

    max_len_seen = 0
    active = 0
    max_active = 0
    delay = 0.0
    _lock = threading.Lock()

    def __init__(self, *args, **kwargs):
        pass

    @classmethod
    def reset(cls):
        cls.max_len_seen = cls.active = cls.max_active = 0
        cls.delay = 0.0

    def encode(self, texts, show_progress_bar=False):
        cls = FakeVectorizer
        with cls._lock:
            cls.active += 1
            cls.max_active = max(cls.max_active, cls.active)
            cls.max_len_seen = max([cls.max_len_seen, *map(len, texts)])
        try:
            if cls.delay:
                time.sleep(cls.delay)
            rows = []
            for text in texts:
                seed = int.from_bytes(hashlib.sha256(text.encode()).digest()[:8], "big")
                rows.append(np.random.default_rng(seed).standard_normal(DIM).astype(np.float32))
            return np.stack(rows)
        finally:
            with cls._lock:
                cls.active -= 1


class ExplodingVectorizer:
    def __init__(self, *args, **kwargs):
        raise OSError("Can't load config for '/vectorizers/x'. model.safetensors is missing")


def write_models(directory: Path, seed: int, skip=()):
    directory.mkdir(parents=True, exist_ok=True)
    for i, spec in enumerate(MODEL_SPECS):
        if spec.filename in skip:
            continue
        torch.manual_seed(seed + i)
        torch.save(ResNetMLP(DIM, spec.output_dim).state_dict(), directory / spec.filename)


@pytest.fixture(autouse=True)
def _reset_fake():
    FakeVectorizer.reset()


@pytest.fixture
def make_app(tmp_path, monkeypatch):
    """Factory: build the server against temp model dirs and enter its lifespan."""
    clients = []

    def make(personal=True, public=False, vectorizer=FakeVectorizer, personal_skip=()):
        dirs = {"personal": tmp_path / "models", "public": tmp_path / "models_public"}
        if personal:
            write_models(dirs["personal"], seed=1, skip=personal_skip)
        else:
            dirs["personal"].mkdir()
        if public:
            write_models(dirs["public"], seed=100)
        else:
            dirs["public"].mkdir()
        monkeypatch.setattr(server, "MODEL_DIRS", dirs)
        monkeypatch.setattr(server, "store", server.ModelStore(dirs))
        monkeypatch.setattr(server, "SentenceTransformer", vectorizer)
        monkeypatch.setattr(server, "RELOAD_CHECK_SECONDS", 0)  # tests opt in explicitly
        client = TestClient(server.app)
        client.__enter__()  # runs the lifespan (loads vectorizer + weights)
        clients.append(client)
        return client, dirs

    yield make
    for client in clients:
        client.__exit__(None, None, None)


def classify(client, body=BODY, variant="personal"):
    return client.post("/classify", json={"mail_body": body, "variant": variant})


# --- wiring guards ------------------------------------------------------------


def test_required_plus_optional_models_cover_every_model_spec():
    """server.REQUIRED_MODELS/OPTIONAL_MODELS are derived from MODEL_SPECS, the
    single source of truth shared with training; a model added to one but not
    the other would silently never load or never be required."""
    names = {spec.filename for spec in MODEL_SPECS}
    assert set(server.REQUIRED_MODELS) | set(server.OPTIONAL_MODELS) == names
    assert not set(server.REQUIRED_MODELS) & set(server.OPTIONAL_MODELS)


def test_server_labels_match_the_taxonomy_width():
    assert len(server.SUB_LABELS) == len(mail_analysis.SubClassificationName)
    assert sum(w for w in mail_analysis.SUB_MODEL_WIDTHS) == len(mail_analysis.SubClassificationName)


def test_server_response_satisfies_the_client_contract(make_app):
    """Every key ai_mail_classifier reads must be in the server's response -
    the two live in different images and can drift independently."""
    import ai_mail_classifier

    client, _ = make_app()
    body = classify(client).json()
    assert set(ai_mail_classifier.REQUIRED_RESULT_KEYS) <= set(body)


# --- health -------------------------------------------------------------------


def test_health_is_ready_with_vectorizer_and_personal_models(make_app):
    client, _ = make_app()
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ready"] is True
    assert body["vectorizer"] == {"loaded": True, "error": None}
    assert body["variants"]["personal"]["ready"] is True
    assert all(m["loaded"] for m in body["variants"]["personal"]["models"].values())


def test_public_variant_without_weights_is_unavailable_but_not_an_outage(make_app):
    client, _ = make_app(public=False)
    body = client.get("/health")
    assert body.status_code == 200
    assert body.json()["variants"]["public"]["ready"] is False

    resp = classify(client, variant="public")
    assert resp.status_code == 503
    assert "Required models unavailable for variant 'public'" in resp.json()["detail"]
    assert "safe_suspicious_30_epochs_model.pth" in resp.json()["detail"]
    # ... and the personal variant is unaffected
    assert classify(client, variant="personal").status_code == 200


def test_health_is_503_when_the_personal_models_are_missing(make_app):
    client, _ = make_app(personal=False)
    resp = client.get("/health")
    assert resp.status_code == 503
    assert resp.json()["ready"] is False
    assert classify(client).status_code == 503


def test_vectorizer_failure_keeps_the_server_up_and_diagnosable(make_app):
    """A vectorizer that cannot load (e.g. the image was built without fetching
    its weights) must not crash startup into a restart loop: /health says why."""
    client, _ = make_app(vectorizer=ExplodingVectorizer)
    health = client.get("/health")
    assert health.status_code == 503
    assert "model.safetensors is missing" in health.json()["vectorizer"]["error"]

    resp = classify(client)
    assert resp.status_code == 503
    assert "Vectorizer unavailable" in resp.json()["detail"]


@pytest.mark.skipif(
    (VECTORIZER_DIR / "model.safetensors").exists(),
    reason="real vectorizer weights present; this reproduces their absence",
)
def test_real_sentence_transformer_without_weights_is_reported_not_raised():
    """Regression for the inference server image shipping only the repo's
    tokenizer files (the weights are fetched at image build time): the real
    SentenceTransformer raises, and ModelStore must turn that into a recorded
    error instead of failing the whole app at startup."""
    store = server.ModelStore({"personal": Path("/nonexistent")})
    store.load_vectorizer(str(VECTORIZER_DIR))
    assert store.vectorizer is None
    assert store.vectorizer_error


@pytest.mark.skipif(
    not (VECTORIZER_DIR / "model.safetensors").exists(),
    reason="vectorizer weights not downloaded (fetched by inference_server/Dockerfile)",
)
def test_real_vectorizer_produces_768_dim_embeddings():
    store = server.ModelStore({"personal": Path("/nonexistent")})
    store.load_vectorizer(str(VECTORIZER_DIR))
    assert store.vectorizer_error is None
    assert store.vectorizer.encode(["hello"], show_progress_bar=False).shape == (1, DIM)


# --- /classify ----------------------------------------------------------------


def test_classify_returns_a_well_formed_result(make_app):
    client, _ = make_app()
    resp = classify(client)
    assert resp.status_code == 200
    body = resp.json()

    assert body["classification"] in {"SAFE", "UNWANTED", "DANGEROUS", "INCONCLUSIVE"}
    assert 0.0 <= float(body["malscore"]) <= 10.0
    assert 0.0 <= float(body["confidence"]) <= 1.0
    assert sum(body["classification_breakdown"].values()) == pytest.approx(1.0, abs=1e-4)
    assert set(body["classification_breakdown"]) == {"SAFE", "UNWANTED", "DANGEROUS"}
    assert set(body["sub_classification_breakdown"]) == {n.name for n in mail_analysis.SubClassificationName}
    assert sum(body["sub_classification_breakdown"].values()) == pytest.approx(1.0, abs=1e-4)
    assert set(body["main_probabilities"]) == {"SAFE", "UNWANTED", "DANGEROUS"}
    assert len(body["sub_probabilities"]) == len(server.SUB_LABELS)
    assert all(v.endswith("%") for v in body["main_probabilities"].values())

    # chromadb_utils does json.loads(report["email_embedding"]) - must be a JSON list
    embedding = json.loads(body["email_embedding"])
    assert len(embedding) == DIM
    assert all(isinstance(x, float) for x in embedding)


def test_classify_is_deterministic(make_app):
    client, _ = make_app()
    assert classify(client).json() == classify(client).json()


def test_contributing_phrases_are_scored_sentences(make_app):
    client, _ = make_app()
    phrases = classify(client).json()["contributing_phrases"]
    assert isinstance(phrases, list)
    sentences = mail_analysis.split_into_sentences(BODY)
    for phrase in phrases:
        assert phrase["text"] in sentences
        assert phrase["impact"] > 0


def test_single_sentence_body_has_no_contributing_phrases(make_app):
    client, _ = make_app()
    resp = classify(client, body="Just one sentence")
    assert resp.status_code == 200
    assert resp.json()["contributing_phrases"] == []


def test_empty_body_is_classified_rather_than_crashing(make_app):
    client, _ = make_app()
    assert classify(client, body="").status_code == 200


def test_unknown_variant_is_a_400_listing_the_valid_ones(make_app):
    client, _ = make_app()
    resp = classify(client, variant="bogus")
    assert resp.status_code == 400
    assert "personal" in resp.json()["detail"] and "public" in resp.json()["detail"]


def test_missing_mail_body_is_a_422(make_app):
    client, _ = make_app()
    assert client.post("/classify", json={"variant": "personal"}).status_code == 422


def test_variants_use_their_own_weights(make_app):
    client, _ = make_app(public=True)
    personal = classify(client, variant="personal").json()
    public = classify(client, variant="public").json()
    assert personal["classification_probabilities"] != public["classification_probabilities"]


def test_missing_unwanted_model_is_tolerated_with_a_zeroed_slice(make_app):
    """The spam/newsletter sub-model is trained last; without it the other
    sub-classes still work and SPAM/NEWSLETTER simply carry no probability."""
    client, _ = make_app(personal_skip=("unwanted_30_epochs_model.pth",))
    assert client.get("/health").status_code == 200
    resp = classify(client)
    assert resp.status_code == 200
    breakdown = resp.json()["sub_classification_breakdown"]
    assert breakdown["SPAM"] == 0.0 and breakdown["NEWSLETTER"] == 0.0


def test_other_missing_models_are_not_tolerated(make_app):
    client, _ = make_app(personal_skip=("dangerous_30_epochs_model.pth",))
    assert client.get("/health").status_code == 503
    resp = classify(client)
    assert resp.status_code == 503
    assert "dangerous_30_epochs_model.pth" in resp.json()["detail"]


def test_truncated_weight_files_are_reported_per_file_not_a_crash(make_app):
    """The weights in the original hand-off were byte-for-byte truncated copies
    (cut at 512 KiB: they still start with a valid zip header but have no
    central directory). Loading must fail soft, say which file and why."""
    client, dirs = make_app(public=True)
    for path in dirs["public"].glob("*.pth"):
        path.write_bytes(path.read_bytes()[:4096])
    client.post("/reload")

    body = client.get("/health").json()
    public = body["variants"]["public"]
    assert public["ready"] is False
    bad = public["models"]["safe_30_epochs_model.pth"]
    assert bad["error"]
    assert classify(client, variant="public").status_code == 503


def test_oversized_body_is_truncated_not_rejected(make_app):
    client, _ = make_app()
    huge = "word " * 600_000  # 3 MB, one run-on "sentence" cluster
    assert classify(client, body=huge).status_code == 200
    assert FakeVectorizer.max_len_seen <= server.MAX_MAIL_CHARS


def test_concurrent_requests_are_bounded_by_the_semaphore(make_app, monkeypatch):
    client, _ = make_app()
    monkeypatch.setattr(server, "_inference_slots", threading.BoundedSemaphore(2))
    FakeVectorizer.delay = 0.05
    results, errors = [], []

    def call():
        try:
            results.append(server.classify(server.ClassifyRequest(mail_body=BODY)))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=call) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]

    assert not errors
    assert len(results) == 8
    assert FakeVectorizer.max_active <= 2


# --- hot reload ---------------------------------------------------------------


def probabilities(client):
    return classify(client).json()["classification_probabilities"]


def test_reload_endpoint_swaps_in_new_weights(make_app):
    client, dirs = make_app()
    before = probabilities(client)

    write_models(dirs["personal"], seed=500)  # what promote.py does: overwrite in place
    resp = client.post("/reload")

    assert resp.status_code == 200
    assert resp.json()["reloaded"]["personal"]
    assert probabilities(client) != before


def test_corrupt_replacement_keeps_the_previous_model_serving(make_app):
    """promote.py overwrites in place, so a request can race a half-written
    file; that must never take a working model out of service."""
    client, dirs = make_app()
    before = probabilities(client)

    (dirs["personal"] / "safe_suspicious_30_epochs_model.pth").write_bytes(b"PK\x03\x04 not a checkpoint")
    resp = client.post("/reload")

    assert resp.status_code == 200
    model = resp.json()["variants"]["personal"]["models"]["safe_suspicious_30_epochs_model.pth"]
    assert model["loaded"] is True
    assert model["error"]
    assert probabilities(client) == before
    assert client.get("/health").status_code == 200


def test_periodic_check_hot_reloads_changed_weights(make_app, monkeypatch):
    client, dirs = make_app()
    before = probabilities(client)

    write_models(dirs["personal"], seed=900)
    monkeypatch.setattr(server, "RELOAD_CHECK_SECONDS", 0.01)
    time.sleep(0.05)

    assert probabilities(client) != before


def test_periodic_check_can_be_disabled(make_app, monkeypatch):
    client, dirs = make_app()
    before = probabilities(client)

    write_models(dirs["personal"], seed=900)
    time.sleep(0.05)

    assert probabilities(client) == before  # RELOAD_CHECK_SECONDS == 0: only /reload refreshes


def test_unchanged_files_are_not_reloaded(make_app):
    client, _ = make_app()
    assert client.post("/reload").json()["reloaded"]["personal"]  # force=True: reloads all
    store = server.store
    assert store.refresh() == {"personal": [], "public": []}  # nothing changed on disk


def test_file_vanishing_mid_promote_keeps_serving(make_app):
    client, dirs = make_app()
    before = probabilities(client)
    (dirs["personal"] / "safe_30_epochs_model.pth").unlink()
    client.post("/reload")
    assert probabilities(client) == before
    assert client.get("/health").status_code == 200


# --- mail_analysis: missing sub-model --------------------------------------------


def test_sub_probabilities_zero_fill_a_missing_model_keeping_the_vector_width():
    models = []
    for i, width in enumerate(mail_analysis.SUB_MODEL_WIDTHS):
        torch.manual_seed(i)
        models.append(ResNetMLP(DIM, width).eval())
    models[1] = None  # the "unwanted" slot
    embedding = np.random.default_rng(0).standard_normal((1, DIM)).astype(np.float32)

    probs = mail_analysis.getSubClassificationProbabilities(
        torch.device("cpu"), models, embedding, np.array([0.5, 0.3, 0.2])
    )

    assert probs.shape == (len(mail_analysis.SubClassificationName),)
    assert (probs[2:4] == 0).all()
    assert probs[:2].sum() == pytest.approx(0.5, abs=1e-5)
    assert probs[4:].sum() == pytest.approx(0.2, abs=1e-5)
