"""The training dataset file the server's training job reads (Analyzers/AIMailAnalyzer/
training/dataset.py), built from ledger rows. Plain Python and NumPy only, no Django: the analyzer
tests import this file by path to read its output with the real reader and to compare the copied
constants below with the training package (Django cannot import torch).
ponytail: copies kept honest by Analyzers/AIMailAnalyzer/tests/test_ledger_export.py; a module
shared by both trees is the upgrade if they grow."""
import hashlib
import io
import json

import numpy as np

# training.recipe.PREPROCESSING_VERSION (Ruling E16): the form ledger rows are embedded in for
# training. Rows in another form are re-embedded (ai_model_reembed_ledger) before any export.
TRAINING_PREPROCESSING = "chunkmean-tokens-v1"
# The encoder's output width (paraphrase-multilingual-mpnet-base-v2): every classifier and campaign
# vector the ledger stores and exports has this many floats.
ENCODER_WIDTH = 768
MIN_HEAD_SAMPLES = 8  # training.gate.MIN_HEAD_SAMPLES
MAX_ROWS = 8000  # training.dataset.MAX_ROWS
NO_CASE = -1  # training.dataset.NO_CASE
# training.recipe.head_target for each of the 8 review folders: {head: {folder: class}}; a folder
# a head does not use is absent.
HEAD_TARGETS = {
    "safe_suspicious": {
        "0_LEGIT_INTERNAL_COMMUNICATION": 0, "0_LEGIT_EXTERNAL_COMMUNICATION": 0,
        "1_SPAM": 1, "1_NEWSLETTER": 1, "2_CLASSIC_PHISHING": 1, "2_CLONE_PHISHING": 1,
        "2_BLACKMAILING_PHISHING": 1, "2_WHALING_PHISHING": 1,
    },
    "spam_dangerous": {
        "1_SPAM": 0, "1_NEWSLETTER": 0, "2_CLASSIC_PHISHING": 1, "2_CLONE_PHISHING": 1,
        "2_BLACKMAILING_PHISHING": 1, "2_WHALING_PHISHING": 1,
    },
    "safe": {"0_LEGIT_INTERNAL_COMMUNICATION": 0, "0_LEGIT_EXTERNAL_COMMUNICATION": 1},
    "unwanted": {"1_SPAM": 0, "1_NEWSLETTER": 1},
    "dangerous": {
        "2_CLASSIC_PHISHING": 0, "2_CLONE_PHISHING": 1, "2_BLACKMAILING_PHISHING": 2,
        "2_WHALING_PHISHING": 3,
    },
}


class DatasetRefused(ValueError):
    """Why the ledger cannot be exported; names rules, heads and folders, never row data."""


def digest(items) -> str:
    """SHA-256 hex of the sorted items as JSON (pairs become lists)."""
    return hashlib.sha256(json.dumps(sorted(list(i) if isinstance(i, tuple) else i for i in items))
                          .encode()).hexdigest()


def _check_heads(folders):
    for head, targets in HEAD_TARGETS.items():
        for cls in sorted(set(targets.values())):
            names = [f for f, c in targets.items() if c == cls]
            n = sum(folders.count(f) for f in names)
            if n < MIN_HEAD_SAMPLES:
                raise DatasetRefused(f"head {head} class {cls} ({', '.join(names)}) has {n} rows, "
                                     f"needs {MIN_HEAD_SAMPLES}")


def _matrix(name, vectors):
    try:
        m = np.asarray(vectors, dtype=np.float32)
    except ValueError:
        raise DatasetRefused(f"{name}: rows of different widths") from None
    if m.ndim != 2 or not m.shape[1]:
        raise DatasetRefused(f"{name}: rows of different widths or empty")
    if m.shape[1] != ENCODER_WIDTH:
        raise DatasetRefused(f"{name}: width {m.shape[1]}, expected {ENCODER_WIDTH}")
    if not np.isfinite(m).all():
        raise DatasetRefused(f"{name}: non-finite values")
    return m


def build_dataset(rows) -> bytes:
    """rows: (folder, classifier vector, campaign vector, case id or None). Returns the npz bytes.
    A case id met again keeps NO_CASE on the later rows (the reader wants case ids unique; the
    first row still lets classify leave the case out of its own neighbours)."""
    rows = list(rows)
    if len(rows) > MAX_ROWS:
        raise DatasetRefused(f"the ledger has {len(rows)} rows, at most {MAX_ROWS} can be trained on")
    folders = [r[0] for r in rows]
    unknown = set(folders) - set(HEAD_TARGETS["safe_suspicious"])
    if unknown:
        raise DatasetRefused(f"{len(unknown)} unknown folder label(s)")
    _check_heads(folders)
    seen, case_ids = set(), []
    for r in rows:
        cid = r[3] if r[3] is not None and r[3] not in seen else NO_CASE
        seen.add(cid)
        case_ids.append(cid)
    buf = io.BytesIO()
    np.savez(buf, embeddings=_matrix("embeddings", [r[1] for r in rows]),
             campaign_embeddings=_matrix("campaign_embeddings", [r[2] for r in rows]),
             folders=np.array(folders, dtype=str), case_ids=np.array(case_ids, dtype=np.int64))
    return buf.getvalue()
