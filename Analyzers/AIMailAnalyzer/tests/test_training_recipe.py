from pathlib import Path

import numpy as np
import pytest
import torch

from training import recipe
from training.recipe import (
    HEADS, PREPROCESSING_VERSION, PREPROCESSING_VERSION_TOKENS, PREPROCESSING_VERSION_WORDS90,
    T_BOUNDS, Heads, Knn,
    Predictions, chunk_by_tokens, chunk_mean_embedding, fit_heads, fit_temperature, fit_temperatures,
    head_target, predict, smooth, temperature_at_bound, truncation_rate,
)

FOLDERS = (
    "0_LEGIT_INTERNAL_COMMUNICATION", "0_LEGIT_EXTERNAL_COMMUNICATION", "1_SPAM", "1_NEWSLETTER",
    "2_CLASSIC_PHISHING", "2_CLONE_PHISHING", "2_BLACKMAILING_PHISHING", "2_WHALING_PHISHING",
)

# The test bed's mapping (lib_spike.head_target), one column per folder above.
EXPECTED = {
    "safe_suspicious": (0, 0, 1, 1, 1, 1, 1, 1),
    "spam_dangerous": (None, None, 0, 0, 1, 1, 1, 1),
    "safe": (0, 1, None, None, None, None, None, None),
    "unwanted": (None, None, 0, 1, None, None, None, None),
    "dangerous": (None, None, None, None, 0, 1, 2, 3),
}


def test_head_target_matches_the_test_bed():
    assert HEADS == tuple(EXPECTED)
    for head, row in EXPECTED.items():
        assert tuple(head_target(head, f) for f in FOLDERS) == row, head


def _synthetic(n_per=4, dim=12, seed=0):
    rng = np.random.default_rng(seed)
    centres = rng.normal(size=(len(FOLDERS), dim)) * 3
    X = np.vstack([centres[i] + rng.normal(size=(n_per, dim)) for i in range(len(FOLDERS))])
    folders = np.repeat(FOLDERS, n_per)
    return X.astype(np.float32), folders


def test_recipe_does_not_oversample():
    src = Path(recipe.__file__).read_text()
    for name in ("SMOTE", "RandomOverSampler", "imblearn"):
        assert name not in src


def test_fit_heads_uses_class_weights_and_every_row_once(monkeypatch):
    X, folders = _synthetic()
    seen, weights, threads = {}, [], []
    real_loader, real_ce = recipe.DataLoader, recipe.nn.CrossEntropyLoss

    def loader(ds, **kw):
        seen[len(seen)] = len(ds)
        threads.append(torch.get_num_threads())
        return real_loader(ds, **kw)

    def ce(weight=None, **kw):
        weights.append(weight)
        return real_ce(weight=weight, **kw)

    monkeypatch.setattr(recipe, "DataLoader", loader)
    monkeypatch.setattr(recipe.nn, "CrossEntropyLoss", ce)
    before = torch.get_num_threads()
    target = 1 if before != 1 else 2
    fit_heads(X, folders, seed=0, epochs=1, threads=target)
    used = [sum(head_target(h, f) is not None for f in folders) for h in HEADS]
    assert list(seen.values()) == used  # no row added, none dropped
    assert all(w is not None for w in weights)
    assert threads == [target] * len(HEADS)
    assert torch.get_num_threads() == before


def test_class_weights_are_balanced(monkeypatch):
    # 4 legit internal, 12 legit external: the "safe" head weighs the rarer class 3x.
    X, folders = _synthetic()
    folders = np.array(list(folders))
    folders[4:8] = "0_LEGIT_EXTERNAL_COMMUNICATION"
    extra = X[8:16]
    X = np.vstack([X, extra])
    folders = np.concatenate([folders, ["0_LEGIT_EXTERNAL_COMMUNICATION"] * 8])
    weights = []
    real_ce = recipe.nn.CrossEntropyLoss
    monkeypatch.setattr(recipe.nn, "CrossEntropyLoss", lambda weight=None: weights.append(weight) or real_ce(weight=weight))
    fit_heads(X, folders, seed=0, epochs=1)
    w = weights[HEADS.index("safe")]
    assert float(w[0] / w[1]) == pytest.approx(3.0)


def test_fit_heads_is_reproducible():
    X, folders = _synthetic()
    a = fit_heads(X, folders, seed=3, epochs=2, threads=1)
    b = fit_heads(X, folders, seed=3, epochs=2, threads=1)
    for h in HEADS:
        for ta, tb in zip(a.models[h].state_dict().values(), b.models[h].state_dict().values()):
            assert torch.equal(ta, tb), h
    knn = Knn.build(X, folders)
    assert np.array_equal(predict(a, knn, X).main, predict(b, knn, X).main)


class _Fixed(torch.nn.Module):
    def __init__(self, logits):
        super().__init__()
        self.logits = torch.tensor(logits, dtype=torch.float32)

    def forward(self, x):
        return self.logits.expand(x.shape[0], -1)


def _softmax(z):
    e = np.exp(z - np.max(z))
    return e / e.sum()


def _hier_heads(logits):
    return Heads({h: _Fixed(v) for h, v in logits.items()}, input_dim=2)


LOGITS = {"safe_suspicious": [0.2, 1.0], "spam_dangerous": [-0.5, 0.5], "safe": [1.0, 0.0],
          "unwanted": [0.0, 0.0], "dangerous": [3.0, 0.0, 0.0, 0.0]}


def _calibrated(p, t):
    """exp_e_combined.softmax_T on an already smoothed probability row."""
    return _softmax(np.log(np.clip(p, 1e-9, 1)) / t)


def test_predict_smooths_and_calibrates_each_component_then_averages():
    # Neighbours at cosine 0.9, 0.8, 0.6, 0.5, 0.0 and a sixth at -1 that 5-NN ignores.
    cos = [0.9, 0.8, 0.6, 0.5, 0.0, -1.0]
    E = np.array([[c, np.sqrt(1 - c**2)] for c in cos])
    labels = np.array([2, 0, 2, 1, 0, 1])
    q = np.array([[2.0, 0.0]])  # unit-normalised inside
    temps = {"hierarchy": 1.7, "knn": 0.6}
    p = predict(_hier_heads(LOGITS), Knn(E, labels), q, temperature=temps)

    ss, sd = _softmax(np.array(LOGITS["safe_suspicious"])), _softmax(np.array(LOGITS["spam_dangerous"]))
    hier = 0.95 * np.array([ss[0], sd[0] * ss[1], sd[1] * ss[1]]) + 0.05 / 3
    w = 1 / (1 - np.array(cos[:5]))
    vote = 0.95 * np.array([w[labels[:5] == c].sum() for c in range(3)]) / w.sum() + 0.05 / 3
    h_cal, k_cal = _calibrated(hier, 1.7), _calibrated(vote, 0.6)
    np.testing.assert_allclose(p.logits["hierarchy"][0], np.log(hier), rtol=1e-5)
    np.testing.assert_allclose(p.logits["knn"][0], np.log(vote), rtol=1e-5)
    np.testing.assert_allclose(p.hierarchy[0], h_cal, rtol=1e-5)
    np.testing.assert_allclose(p.knn[0], k_cal, rtol=1e-5)
    np.testing.assert_allclose(p.main[0], (h_cal + k_cal) / 2, rtol=1e-5)
    np.testing.assert_allclose(p.main.sum(1), 1, rtol=1e-6)
    np.testing.assert_allclose(p.sub["dangerous"][0], _softmax(np.array(LOGITS["dangerous"])), rtol=1e-5)
    for v in p.sub.values():
        np.testing.assert_allclose(v.sum(1), 1, rtol=1e-6)


def test_default_temperature_is_one_per_component():
    knn = Knn(np.array([[1.0, 0.0]] * 5), np.array([0, 1, 2, 0, 0]))
    a = predict(_hier_heads(LOGITS), knn, np.ones((1, 2)))
    b = predict(_hier_heads(LOGITS), knn, np.ones((1, 2)), temperature={"hierarchy": 1.0, "knn": 1.0})
    np.testing.assert_allclose(a.main, b.main)
    np.testing.assert_allclose(a.hierarchy, np.exp(a.logits["hierarchy"]), rtol=1e-6)  # T=1 is a no-op
    np.testing.assert_allclose(smooth(np.eye(3))[0], [0.95 + 0.05 / 3, 0.05 / 3, 0.05 / 3])


def test_one_hot_knn_vote_has_finite_logits_and_its_own_temperature():
    knn = Knn(np.array([[1.0, 0.0]] * 5), np.zeros(5, dtype=int))  # unanimous: one-hot vote
    p = predict(_hier_heads(LOGITS), knn, np.ones((1, 2)), temperature={"hierarchy": 1.0, "knn": 2.0})
    assert np.isfinite(p.logits["knn"]).all()
    np.testing.assert_allclose(p.logits["knn"][0], np.log([0.95 + 0.05 / 3, 0.05 / 3, 0.05 / 3]), rtol=1e-6)
    np.testing.assert_allclose(p.knn[0], _calibrated(np.exp(p.logits["knn"][0]), 2.0), rtol=1e-6)


def test_knn_vote_on_an_empty_index_raises():
    with pytest.raises(ValueError, match="empty neighbour index"):
        Knn(np.zeros((0, 2)), np.zeros(0, dtype=int)).vote(np.ones((1, 2)))


def _sampled(scale, n=20000, seed=0):
    rng = np.random.default_rng(seed)
    z = rng.normal(size=(n, 3)) * 2
    p = np.exp(z) / np.exp(z).sum(1, keepdims=True)
    y = np.array([rng.choice(3, p=row) for row in p])
    return z * scale, y


def test_fit_temperature_is_one_for_calibrated_logits():
    z, y = _sampled(1.0)
    assert fit_temperature(z, y) == pytest.approx(1.0, abs=0.08)


def test_fit_temperature_cools_overconfident_logits_without_changing_argmax():
    z, y = _sampled(3.0)
    t = fit_temperature(z, y)
    assert t > 1.5
    assert np.array_equal((z / t).argmax(1), z.argmax(1))


class _FakeVectorizer:
    """Encodes a chunk as [word count, 1]; a token per character-ish: 2 tokens per word."""

    max_seq_length = 20

    def __init__(self):
        self.calls = []
        self.tokenizer = self

    def encode(self, chunks, add_special_tokens=True, **kw):
        if isinstance(chunks, str):  # tokenizer role: 2 tokens per word, + CLS/SEP
            return [0] * (2 * len(chunks.split()) + (2 if add_special_tokens else 0))
        self.calls.append(list(chunks))
        return np.array([[len(c.split()), 1.0] for c in chunks], dtype=np.float32)


def test_chunk_mean_embedding_averages_90_word_chunks_up_to_8():
    v = _FakeVectorizer()
    text = " ".join(["w"] * 200)
    e = chunk_mean_embedding(v, text, by_tokens=False)
    assert [len(c.split()) for c in v.calls[0]] == [90, 90, 20]
    np.testing.assert_allclose(e, [200 / 3, 1.0])
    chunk_mean_embedding(v, " ".join(["w"] * 2000), by_tokens=False)
    assert len(v.calls[1]) == 8
    assert v.calls[1][0].split() == ["w"] * 90
    np.testing.assert_allclose(chunk_mean_embedding(v, "", by_tokens=False), [0.0, 1.0])


def test_chunk_mean_embedding_defaults_to_token_chunks():
    # Ruling E16: the window is 20 tokens, so 9 words per chunk (18 + CLS/SEP).
    v = _FakeVectorizer()
    text = " ".join(["w"] * 25)
    np.testing.assert_allclose(chunk_mean_embedding(v, text), [25 / 3, 1.0])
    assert [len(c.split()) for c in v.calls[0]] == [9, 9, 7]
    assert PREPROCESSING_VERSION == PREPROCESSING_VERSION_TOKENS


def test_truncation_rate_counts_chunks_over_the_window():
    v = _FakeVectorizer()  # window 20 tokens: 9 words fit (18 + 2), 10 do not (22)
    assert truncation_rate(v, ["a " * 9, "a " * 10], words=90) == pytest.approx(0.5)
    assert truncation_rate(v, ["a " * 18], words=9) == 0.0


def test_chunk_by_tokens_fits_the_window():
    v = _FakeVectorizer()
    chunks = chunk_by_tokens(v, " ".join(str(i) for i in range(25)))
    assert [len(c.split()) for c in chunks] == [9, 9, 7]
    assert " ".join(chunks).split() == [str(i) for i in range(25)]
    assert len(chunk_by_tokens(v, "a " * 1000)) == 8
    e = chunk_mean_embedding(v, " ".join(["w"] * 25), by_tokens=True)
    np.testing.assert_allclose(e, [25 / 3, 1.0])


def test_fit_temperatures_fits_one_per_component():
    zc, y = _sampled(1.0)
    zh = zc * 3.0  # over-confident hierarchy, calibrated knn
    softmax = lambda z: np.exp(z) / np.exp(z).sum(1, keepdims=True)
    preds = Predictions(main=None, hierarchy=None, knn=None, sub={},
                        logits={"hierarchy": np.log(softmax(zh)), "knn": np.log(softmax(zc))})
    t = fit_temperatures(preds, y)
    assert set(t) == {"hierarchy", "knn"}
    assert t["hierarchy"] > 1.5 and t["knn"] == pytest.approx(1.0, abs=0.08)


def test_temperature_at_bound():
    lo, hi = T_BOUNDS
    assert (lo, hi) == (0.2, 30)
    assert temperature_at_bound(lo) and temperature_at_bound(lo + 5e-7)
    assert temperature_at_bound(hi) and temperature_at_bound(hi - 5e-7)
    assert not temperature_at_bound(1.0) and not temperature_at_bound(lo + 1e-3)


def test_fit_heads_restores_threads_when_it_raises():
    X, folders = _synthetic()
    keep = np.array([not f.startswith("2_") for f in folders])  # the dangerous head has no rows
    before = torch.get_num_threads()
    with pytest.raises(ValueError, match="dangerous"):
        fit_heads(X[keep], folders[keep], seed=0, epochs=1, threads=1 if before != 1 else 2)
    assert torch.get_num_threads() == before


def test_heads_record_their_input_dim():
    X, folders = _synthetic(dim=12)
    assert fit_heads(X, folders, seed=0, epochs=1, threads=1).input_dim == 12


def test_preprocessing_versions_name_the_chunking():
    assert PREPROCESSING_VERSION_WORDS90 == "chunkmean-words90-v1"
    assert PREPROCESSING_VERSION_TOKENS == "chunkmean-tokens-v1"
