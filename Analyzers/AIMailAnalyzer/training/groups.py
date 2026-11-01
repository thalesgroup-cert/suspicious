"""Connected-component groups that splits, calibration and the gate must never separate."""
import numpy as np
from scipy.sparse import csr_matrix
from scipy.sparse.csgraph import connected_components


def _cosine(X: np.ndarray) -> np.ndarray:
    # ponytail: dense n x n similarity, fine for ledgers of a few thousand rows; switch to a
    # radius-neighbours graph if the ledger grows past ~20k rows.
    X = np.asarray(X, dtype=np.float64)
    Xn = X / np.maximum(np.linalg.norm(X, axis=1, keepdims=True), 1e-12)
    return Xn @ Xn.T


def _components(adjacency: np.ndarray) -> np.ndarray:
    return connected_components(csr_matrix(adjacency), directed=False)[1]


def near_duplicate_groups(embeddings: np.ndarray, threshold: float = 0.95) -> np.ndarray:
    """Component id per row; rows at cosine similarity >= threshold are joined."""
    return _components(_cosine(embeddings) >= threshold)


def campaign_groups(campaign_embeddings, distance_threshold: float, ties: list[tuple[int, int]]) -> np.ndarray:
    """Component id per row; rows within cosine distance distance_threshold are joined, and so is
    every (i, j) pair in ties (the CampaignMember links)."""
    adjacency = (1.0 - _cosine(campaign_embeddings)) <= distance_threshold
    for i, j in ties:
        adjacency[i, j] = adjacency[j, i] = True
    return _components(adjacency)
