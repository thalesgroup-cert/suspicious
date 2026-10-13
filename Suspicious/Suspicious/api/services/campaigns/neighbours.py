"""
Embedding-space indicators on the PCA sample: near-known-bad and novel messages.

Both are heuristics: closeness in embedding space is a hint, not proof of the
same campaign.

- near_known_bad: non-dangerous messages whose K nearest neighbours (cosine
  similarity, self excluded) are at least BAD_SHARE_THRESHOLD Dangerous and
  which are themselves "near": their nearest-neighbour distance is within the
  NOVELTY_PERCENTILE percentile of the sample's nearest-neighbour distances
  (<=, so equal spacing excludes nothing). An isolated message is novel, not
  near known bad, even when its distant neighbours are Dangerous.
  score = that share.
- novel: messages dated within the last NOVEL_WINDOW_DAYS UTC days (today
  included) whose nearest-neighbour cosine distance exceeds the
  NOVELTY_PERCENTILE percentile of the sample's nearest-neighbour distances;
  score = that distance.

Memory bound: the sample is the PCA one (at most MAX_PCA_LIMIT = 5000 vectors
of the dominant dimension). Similarity is computed in float32 chunks of at
most CHUNK_ROWS rows against the whole normalised matrix, never n x n: for
5000 x 768 vectors the float32 matrix is ~15 MB and one chunk's similarity block
(512 x 5000) ~10 MB plus ~20 MB of int64 argpartition indices; measured peak
(tracemalloc) ~68 MB for 5000 x 768, on top of the sampled records, and it does
not grow with the store since the sample is capped.
Zero vectors have no direction: they are dropped before the scan (never a
neighbour, never listed, no NaN).
"""
import logging
from datetime import timedelta, timezone as dt_timezone
from typing import Any, Dict, List

import numpy as np
from django.core.cache import cache

from .chroma import get_chroma_collection
from .metadata import (
    CLASSIFICATION_DANGEROUS,
    extract_case_id,
    extract_mail_subject,
    extract_metadata_datetime,
    normalize_classification,
)
from .service import fetch_dominant_sample
from .summary import _now

logger = logging.getLogger(__name__)

K = 10
BAD_SHARE_THRESHOLD = 0.6
NOVELTY_PERCENTILE = 95
NOVEL_WINDOW_DAYS = 7
MAX_ITEMS = 20
CHUNK_ROWS = 512
CACHE_TTL_SECONDS = 120
SCORE_DECIMALS = 6  # chunk shape may change float32 matmul in the last bits


def empty_neighbours_payload() -> Dict[str, Any]:
    return {
        "k": K,
        "bad_share_threshold": BAD_SHARE_THRESHOLD,
        "novelty_percentile": NOVELTY_PERCENTILE,
        "novel_window_days": NOVEL_WINDOW_DAYS,
        "near_known_bad": [],
        "novel": [],
    }


def _nearest(X: np.ndarray):
    """(indices, similarities) of the K nearest rows of each row, self excluded,
    most similar first. X: n x d float32, rows unit length, n > K."""
    n = X.shape[0]
    nn_idx = np.empty((n, K), dtype=np.int64)
    nn_sim = np.empty((n, K), dtype=np.float32)
    for start in range(0, n, CHUNK_ROWS):
        sim = X[start:start + CHUNK_ROWS] @ X.T
        np.clip(sim, -1.0, 1.0, out=sim)
        rows = np.arange(sim.shape[0])
        sim[rows, start + rows] = -np.inf
        part = np.argpartition(sim, n - K, axis=1)[:, n - K:]
        part_sim = np.take_along_axis(sim, part, axis=1)
        order = np.argsort(-part_sim, axis=1, kind="stable")
        stop = start + sim.shape[0]
        nn_idx[start:stop] = np.take_along_axis(part, order, axis=1)
        nn_sim[start:stop] = np.take_along_axis(part_sim, order, axis=1)
    return nn_idx, nn_sim


def _ranked(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    items.sort(key=lambda i: (
        -i["score"],
        -(i["date"].toordinal() if i["date"] else 0),
        i["suspicious_case_id"] or "",
    ))
    return items[:MAX_ITEMS]


def compute_neighbours(selected) -> Dict[str, Any]:
    payload = empty_neighbours_payload()
    if not selected:
        return payload

    X = np.array([vector for _, vector, _ in selected], dtype=np.float32)
    norms = np.linalg.norm(X, axis=1)
    keep = norms > 0
    X = X[keep]
    X /= norms[keep, None]
    metas = [meta for (_, _, meta), kept in zip(selected, keep) if kept]
    if len(metas) < K + 1:
        return payload

    dangerous = np.array([
        normalize_classification(m.get("classification")) == CLASSIFICATION_DANGEROUS
        for m in metas
    ])
    dates = []
    for m in metas:
        sent_dt = extract_metadata_datetime(m)
        dates.append(sent_dt.astimezone(dt_timezone.utc).date() if sent_dt else None)

    nn_idx, nn_sim = _nearest(X)
    shares = dangerous[nn_idx].sum(axis=1) / K
    distances = 1.0 - nn_sim[:, 0].astype(np.float64)
    novelty_cut = float(np.percentile(distances, NOVELTY_PERCENTILE))
    today = _now().date()
    window_start = today - timedelta(days=NOVEL_WINDOW_DAYS - 1)

    def item(i, score, nearest_dangerous=None):
        return {
            "suspicious_case_id": extract_case_id(metas[i]),
            "mail_subject": extract_mail_subject(metas[i]),
            "label": normalize_classification(metas[i].get("classification")),
            "date": dates[i],
            "score": round(float(score), SCORE_DECIMALS),
            "nearest_dangerous_case_id": nearest_dangerous,
        }

    near_bad, novel = [], []
    for i in range(len(metas)):
        isolated = distances[i] > novelty_cut
        if not dangerous[i] and shares[i] >= BAD_SHARE_THRESHOLD and not isolated:
            j = next(j for j in nn_idx[i] if dangerous[j])  # most similar dangerous
            near_bad.append(item(i, shares[i], extract_case_id(metas[j])))
        if isolated and dates[i] and window_start <= dates[i] <= today:
            novel.append(item(i, distances[i]))

    payload["near_known_bad"] = _ranked(near_bad)
    payload["novel"] = _ranked(novel)
    return payload


def get_campaign_neighbours(limit: int) -> Dict[str, Any]:
    key = f"campaigns:neighbours:{limit}"
    cached = cache.get(key)
    if cached is not None:
        return cached

    collection = get_chroma_collection()
    if collection is None:
        return empty_neighbours_payload()

    try:
        sampled_ids, selected, _, _ = fetch_dominant_sample(collection, limit)
        if not sampled_ids:
            return empty_neighbours_payload()
        payload = compute_neighbours(selected)
    except Exception as exc:
        logger.error("Error computing campaign neighbours: %s", exc, exc_info=True)
        return empty_neighbours_payload()  # never cached

    cache.set(key, payload, CACHE_TTL_SECONDS)
    return payload
