from pathlib import Path

import numpy as np
import pytest
import torch

from training import recipe
from training.recipe import (
    HEADS, Heads, Knn, chunk_by_tokens, chunk_mean_embedding, fit_heads, fit_temperature,
    head_target, predict, truncation_rate,
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
    a = fit_heads(X, folders, seed=3, epochs=2)
    b = fit_heads(X, folders, seed=3, epochs=2)
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


def test_predict_blends_hierarchy_and_distance_weighted_knn():
    logits = {"safe_suspicious": [0.2, 1.0], "spam_dangerous": [-0.5, 0.5], "safe": [1.0, 0.0],
              "unwanted": [0.0, 0.0], "dangerous": [3.0, 0.0, 0.0, 0.0]}
    heads = Heads({h: _Fixed(v) for h, v in logits.items()})
    # Neighbours at cosine 0.9, 0.8, 0.6, 0.5, 0.0 and a sixth at -1 that 5-NN ignores.
    cos = [0.9, 0.8, 0.6, 0.5, 0.0, -1.0]
    E = np.array([[c, np.sqrt(1 - c**2)] for c in cos])
    labels = np.array([2, 0, 2, 1, 0, 1])
    knn = Knn(E, labels)
    q = np.array([[2.0, 0.0]])  # unit-normalised inside
    p = predict(heads, knn, q)

    ss, sd = _softmax(np.array(logits["safe_suspicious"])), _softmax(np.array(logits["spam_dangerous"]))
    hier = np.array([ss[0], sd[0] * ss[1], sd[1] * ss[1]])
    w = 1 / (1 - np.array(cos[:5]))
    vote = np.array([w[labels[:5] == c].sum() for c in range(3)]) / w.sum()
    np.testing.assert_allclose(p.hierarchy[0], hier, rtol=1e-5)
    np.testing.assert_allclose(p.knn[0], vote, rtol=1e-5)
    np.testing.assert_allclose(p.main[0], (hier + vote) / 2, rtol=1e-5)
    np.testing.assert_allclose(p.main.sum(1), 1, rtol=1e-6)
    np.testing.assert_allclose(p.sub["dangerous"][0], _softmax(np.array(logits["dangerous"])), rtol=1e-5)
    for v in p.sub.values():
        np.testing.assert_allclose(v.sum(1), 1, rtol=1e-6)


def test_predict_applies_the_temperature_to_the_hierarchy():
    logits = {"safe_suspicious": [0.0, 2.0], "spam_dangerous": [0.0, 1.0], "safe": [0.0, 0.0],
              "unwanted": [0.0, 0.0], "dangerous": [0.0, 0.0, 0.0, 0.0]}
    knn = Knn(np.array([[1.0, 0.0]] * 5), np.array([0, 0, 0, 0, 0]))
    raw = predict(Heads({h: _Fixed(v) for h, v in logits.items()}), knn, np.ones((1, 2)))
    hot = predict(Heads({h: _Fixed(v) for h, v in logits.items()}, temperature=2.0), knn, np.ones((1, 2)))
    expected = _softmax(np.log(raw.hierarchy[0]) / 2.0)
    np.testing.assert_allclose(hot.hierarchy[0], expected, rtol=1e-5)
    np.testing.assert_allclose(raw.logits, np.log(raw.hierarchy), rtol=1e-5)


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
    e = chunk_mean_embedding(v, text)
    assert [len(c.split()) for c in v.calls[0]] == [90, 90, 20]
    np.testing.assert_allclose(e, [200 / 3, 1.0])
    chunk_mean_embedding(v, " ".join(["w"] * 2000))
    assert len(v.calls[1]) == 8
    assert v.calls[1][0].split() == ["w"] * 90
    np.testing.assert_allclose(chunk_mean_embedding(v, ""), [0.0, 1.0])


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
