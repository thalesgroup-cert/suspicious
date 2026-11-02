"""The training dataset (Task 8's ledger export), downloaded by the server through a presigned URL,
so untrusted bytes. An uncompressed npz with exactly four arrays, one row per ledger mail:
`embeddings` (float32 (n, d), the classifier input, token chunk-mean), `campaign_embeddings`
(float32 (n, d2), the first-128 cmp-e1 vector that the groups are built from, Ruling E18),
`folders` (fixed-width unicode, one of FOLDERS) and `case_ids` (int64, unique). No mail text.
The archive goes through bundle.py's checks (stored members only, layout as np.savez writes it,
every array header consistent with its member) before np.load(allow_pickle=False) reads it."""
import io
import os
import stat
from dataclasses import dataclass

import numpy as np

from training.bundle import MAX_INPUT_DIM, BundleError, _npz_shapes

MAX_DATASET_BYTES = 200 * 2**20  # Ruling E9's download cap
MAX_ROWS = 8000  # groups.py's ceiling: its dense n x n similarity costs about 0.33 GB at 8k rows
MAX_FOLDER_CHARS = 64
FOLDERS = (
    "0_LEGIT_INTERNAL_COMMUNICATION", "0_LEGIT_EXTERNAL_COMMUNICATION", "1_SPAM", "1_NEWSLETTER",
    "2_CLASSIC_PHISHING", "2_CLONE_PHISHING", "2_BLACKMAILING_PHISHING", "2_WHALING_PHISHING",
)
ARRAYS = ("embeddings", "campaign_embeddings", "folders", "case_ids")


class DatasetError(Exception):
    """Names the array or the rule, never the data."""


@dataclass
class Dataset:
    embeddings: np.ndarray
    campaign_embeddings: np.ndarray
    folders: np.ndarray
    case_ids: np.ndarray


def _read(path) -> bytes:
    try:
        fd = os.open(os.fspath(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise DatasetError("dataset: cannot open") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise DatasetError("dataset: not a regular file")
        if st.st_size > MAX_DATASET_BYTES:
            raise DatasetError("dataset: size above the cap")
        with os.fdopen(os.dup(fd), "rb") as fh:
            data = fh.read(MAX_DATASET_BYTES + 1)
        if len(data) > MAX_DATASET_BYTES:
            raise DatasetError("dataset: size above the cap")
        return data
    finally:
        os.close(fd)


def _matrix(name, shape, dtype, rows=None):
    if dtype != np.float32 or len(shape) != 2 or not 1 <= shape[1] <= MAX_INPUT_DIM:
        raise DatasetError(f"{name}: must be float32 (rows, 1..{MAX_INPUT_DIM})")
    if rows is not None and shape[0] != rows:
        raise DatasetError(f"{name}: row count differs from embeddings")


def read_dataset(path) -> Dataset:
    data = _read(path)
    try:
        shapes = _npz_shapes(data, "dataset", MAX_DATASET_BYTES)
    except BundleError as e:
        raise DatasetError(str(e)) from None
    if set(shapes) != set(ARRAYS):
        raise DatasetError(f"dataset: arrays must be exactly {', '.join(ARRAYS)}")
    shape, dtype = shapes["embeddings"]
    _matrix("embeddings", shape, dtype)
    n = shape[0]
    if not 1 <= n <= MAX_ROWS:
        raise DatasetError(f"embeddings: 1 to {MAX_ROWS} rows")
    _matrix("campaign_embeddings", *shapes["campaign_embeddings"], rows=n)
    shape, dtype = shapes["folders"]
    if dtype.kind != "U" or dtype.itemsize > 4 * MAX_FOLDER_CHARS or shape != (n,):
        raise DatasetError("folders: must be short unicode strings, one per row")
    shape, dtype = shapes["case_ids"]
    if dtype != np.int64 or shape != (n,):
        raise DatasetError("case_ids: must be int64, one per row")
    try:
        with np.load(io.BytesIO(data), allow_pickle=False) as npz:
            arrays = {k: npz[k] for k in ARRAYS}
    except Exception:
        raise DatasetError("dataset: unreadable arrays") from None
    for k in ("embeddings", "campaign_embeddings"):
        if not np.isfinite(arrays[k]).all():
            raise DatasetError(f"{k}: non-finite values")
    if not np.isin(arrays["folders"], FOLDERS).all():
        raise DatasetError("folders: unknown folder name")
    if len(np.unique(arrays["case_ids"])) != n:
        raise DatasetError("case_ids: must be unique")
    return Dataset(**arrays)
