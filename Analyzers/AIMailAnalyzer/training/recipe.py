"""The retrain recipe (spec section 5), ported from the test bed (lib_spike.py, exp_e_combined.py,
exp_a2_calibrate.py): five ResNetMLP heads with class weights only, the main decision the mean of
the temperature-calibrated head hierarchy and a distance-weighted cosine 5-NN vote."""
from dataclasses import dataclass

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from scipy.optimize import minimize_scalar
from sklearn.utils.class_weight import compute_class_weight
from torch.utils.data import DataLoader, TensorDataset

from ResNetMLP import ResNetMLP

HEADS = ("safe_suspicious", "spam_dangerous", "safe", "unwanted", "dangerous")
NUM_OUT = {"safe_suspicious": 2, "spam_dangerous": 2, "safe": 2, "unwanted": 2, "dangerous": 4}
DANGEROUS_ORDER = {"2_CLASSIC_PHISHING": 0, "2_CLONE_PHISHING": 1, "2_BLACKMAILING_PHISHING": 2,
                   "2_WHALING_PHISHING": 3}
SUB_HEADS = ("safe", "unwanted", "dangerous")
K = 5
TRUNCATION_LIMIT = 0.05  # Ruling E11: above this share of truncated chunks, chunk by tokens


def head_target(head: str, folder: str) -> int | None:
    """Target class of a folder for a head, None when the head does not use the row."""
    if head == "safe_suspicious":
        return 0 if folder.startswith("0_") else 1
    if head == "spam_dangerous":
        if folder.startswith("0_"):
            return None
        return 0 if folder.startswith("1_") else 1
    if head == "safe":
        if not folder.startswith("0_"):
            return None
        return 0 if folder == "0_LEGIT_INTERNAL_COMMUNICATION" else 1
    if head == "unwanted":
        if not folder.startswith("1_"):
            return None
        return 0 if folder == "1_SPAM" else 1
    if head == "dangerous":
        return DANGEROUS_ORDER.get(folder)
    raise ValueError(f"unknown head {head}")


def main_class(folder: str) -> int:
    """0 Safe, 1 Unwanted, 2 Dangerous: the folder's digit prefix."""
    return int(folder[0])


# --- text to embedding -------------------------------------------------------------------------

def _word_chunks(text: str, words: int, max_chunks: int) -> list[str]:
    w = text.split()
    return [" ".join(w[i:i + words]) for i in range(0, len(w), words)][:max_chunks] or [""]


def chunk_by_tokens(vectorizer, text: str, *, max_chunks: int = 8) -> list[str]:
    """Greedy word chunks that fit the encoder window (max_seq_length, special tokens included).
    A single word longer than the window gets a chunk of its own (the encoder truncates it)."""
    tok = vectorizer.tokenizer
    budget = vectorizer.max_seq_length - len(tok.encode("", add_special_tokens=True))
    chunks, cur, used = [], [], 0
    for word in text.split():
        n = len(tok.encode(word, add_special_tokens=False))
        if cur and used + n > budget:
            chunks.append(" ".join(cur))
            if len(chunks) == max_chunks:
                return chunks
            cur, used = [], 0
        cur.append(word)
        used += n
    if cur:
        chunks.append(" ".join(cur))
    return chunks[:max_chunks] or [""]


def chunk_mean_embedding(vectorizer, text: str, *, words: int = 90, max_chunks: int = 8,
                         by_tokens: bool = False) -> np.ndarray:
    """Mean of the embeddings of the text's chunks (90 words, at most 8; or token-sized)."""
    chunks = chunk_by_tokens(vectorizer, text, max_chunks=max_chunks) if by_tokens \
        else _word_chunks(text, words, max_chunks)
    return np.asarray(vectorizer.encode(chunks), dtype=np.float32).mean(axis=0)


def truncation_rate(vectorizer, texts, words: int = 90) -> float:
    """Share of word chunks whose token count (special tokens included) exceeds the window."""
    counts = [len(vectorizer.tokenizer.encode(c)) for t in texts for c in _word_chunks(t, words, 8)]
    return sum(n > vectorizer.max_seq_length for n in counts) / max(len(counts), 1)


# --- heads ---------------------------------------------------------------------------------------

@dataclass
class Heads:
    models: dict  # head name -> trained ResNetMLP (eval mode)
    temperature: float = 1.0  # for the main hierarchy; fitted on held-out groups by the caller


def _train_head(X, y, num_classes, seed, epochs):
    torch.manual_seed(seed)
    Xt, yt = torch.tensor(X, dtype=torch.float32), torch.tensor(y, dtype=torch.long)
    loader = DataLoader(TensorDataset(Xt, yt), batch_size=32, shuffle=True,
                        generator=torch.Generator().manual_seed(seed))
    model = ResNetMLP(Xt.shape[1], num_classes)
    present = np.unique(y)
    weight = np.ones(num_classes)
    weight[present] = compute_class_weight(class_weight="balanced", classes=present, y=y)
    crit = nn.CrossEntropyLoss(weight=torch.tensor(weight, dtype=torch.float32))
    opt = optim.Adam(model.parameters(), lr=0.001)
    model.train()
    for _ in range(epochs):
        for xb, yb in loader:
            loss = crit(model(xb), yb)
            opt.zero_grad()
            loss.backward()
            opt.step()
    return model.eval()


def fit_heads(X, folders, *, seed: int, epochs: int = 30, threads: int = 2) -> Heads:
    """Train the five heads on the rows each head uses. Class weights only, no resampling.
    The minimum-samples rule is the gate's (check 4); here a head without rows is an error."""
    X = np.asarray(X, dtype=np.float32)
    previous = torch.get_num_threads()
    torch.set_num_threads(threads)
    try:
        models = {}
        for head in HEADS:
            rows = [(i, t) for i, f in enumerate(folders) if (t := head_target(head, f)) is not None]
            if not rows:
                raise ValueError(f"head {head} has no training rows")
            idx, y = zip(*rows)
            models[head] = _train_head(X[list(idx)], np.array(y), NUM_OUT[head], seed, epochs)
        return Heads(models)
    finally:
        torch.set_num_threads(previous)


# --- neighbours and prediction -------------------------------------------------------------------

def _unit(X):
    X = np.asarray(X, dtype=np.float64)
    return X / np.maximum(np.linalg.norm(X, axis=1, keepdims=True), 1e-12)


@dataclass
class Knn:
    embeddings: np.ndarray  # labelled embeddings, one row per ledger mail
    labels: np.ndarray  # main class 0/1/2 per row
    case_ids: np.ndarray | None = None

    @classmethod
    def build(cls, X, folders, case_ids=None):
        return cls(np.asarray(X, dtype=np.float32), np.array([main_class(f) for f in folders]), case_ids)

    def vote(self, X) -> np.ndarray:
        """Distance-weighted cosine 5-NN class probabilities (sklearn's weights="distance":
        1/d, and exact matches take the whole vote)."""
        d = 1.0 - _unit(X) @ _unit(self.embeddings).T
        k = min(K, d.shape[1])
        nn_idx = np.argsort(d, axis=1, kind="stable")[:, :k]
        nd = np.take_along_axis(d, nn_idx, axis=1)
        exact = nd <= 1e-12
        w = np.where(exact.any(1, keepdims=True), exact.astype(float), 1.0 / np.maximum(nd, 1e-12))
        out = np.zeros((len(d), 3))
        for c in range(3):
            out[:, c] = (w * (self.labels[nn_idx] == c)).sum(1)
        return out / out.sum(1, keepdims=True)


@dataclass
class Predictions:
    main: np.ndarray  # (n, 3) Safe/Unwanted/Dangerous: mean of hierarchy and knn
    hierarchy: np.ndarray  # (n, 3) calibrated head hierarchy
    knn: np.ndarray  # (n, 3) neighbour vote
    logits: np.ndarray  # (n, 3) log of the uncalibrated hierarchy, what fit_temperature takes
    sub: dict  # "safe" (n, 2), "unwanted" (n, 2), "dangerous" (n, 4)


def _softmax(z):
    z = z - z.max(1, keepdims=True)
    e = np.exp(z)
    return e / e.sum(1, keepdims=True)


def predict(heads: Heads, knn: Knn, X) -> Predictions:
    Xt = torch.tensor(np.asarray(X), dtype=torch.float32)
    with torch.no_grad():
        p = {h: torch.softmax(m.eval()(Xt), dim=1).double().numpy() for h, m in heads.models.items()}
    ss, sd = p["safe_suspicious"], p["spam_dangerous"]
    raw = np.stack([ss[:, 0], sd[:, 0] * ss[:, 1], sd[:, 1] * ss[:, 1]], axis=1)  # combine_main
    logits = np.log(np.clip(raw, 1e-12, 1.0))
    hierarchy = _softmax(logits / heads.temperature)
    vote = knn.vote(X)
    return Predictions((hierarchy + vote) / 2, hierarchy, vote, logits, {h: p[h] for h in SUB_HEADS})


def fit_temperature(logits, labels) -> float:
    """One temperature minimising the NLL of softmax(logits / T) (Ruling E5). Fit it on held-out
    groups only. T > 0, so the argmax never changes."""
    z, y = np.asarray(logits, dtype=np.float64), np.asarray(labels)

    def nll(t):
        q = _softmax(z / t)
        return -np.mean(np.log(np.clip(q[np.arange(len(y)), y], 1e-12, 1.0)))

    return float(minimize_scalar(nll, bounds=(0.2, 30), method="bounded").x)
