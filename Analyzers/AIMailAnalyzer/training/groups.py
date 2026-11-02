"""Connected-component groups that splits, calibration and the gate must never separate."""
import numpy as np
from scipy.sparse import csr_matrix
from scipy.sparse.csgraph import connected_components


def _cosine(X: np.ndarray) -> np.ndarray:
    # ponytail: dense n x n float32 similarity (4 n^2 bytes) plus the boolean adjacency (n^2).
    # Measured extra peak, 768-dim, few edges: 0.12 GB at 5k rows, 0.33 GB at 8k, 1.9 GB at 20k;
    # each joined pair adds about 12 bytes in the sparse graph. Ceiling about 8k rows beside the
    # encoder; past that, switch to a radius-neighbours graph. training.dataset.MAX_ROWS enforces it
    # for the server's training job.
    X = np.asarray(X, dtype=np.float32)
    Xn = X / np.maximum(np.linalg.norm(X, axis=1, keepdims=True), np.float32(1e-12))
    return Xn @ Xn.T


def _components(adjacency: np.ndarray) -> np.ndarray:
    return connected_components(csr_matrix(adjacency), directed=False)[1]


def near_duplicate_groups(embeddings: np.ndarray, threshold: float = 0.95) -> np.ndarray:
    """Component id per row; rows at cosine similarity >= threshold are joined."""
    return _components(_cosine(embeddings) >= threshold)


def campaign_groups(campaign_embeddings, distance_threshold: float, ties: list[tuple[int, int]]) -> np.ndarray:
    """Component id per row; rows within cosine distance distance_threshold are joined, and so is
    every (i, j) pair in ties (the CampaignMember links)."""
    adjacency = _cosine(campaign_embeddings) >= 1.0 - distance_threshold
    for i, j in ties:
        adjacency[i, j] = adjacency[j, i] = True
    return _components(adjacency)
