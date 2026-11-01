import numpy as np

from training.groups import campaign_groups, near_duplicate_groups


def _pair(cos):
    """Two unit vectors in 2D with the given cosine similarity."""
    return np.array([[1.0, 0.0], [cos, np.sqrt(1 - cos**2)]])


def _same(g, i, j):
    return g[i] == g[j]


def test_near_duplicates_at_097_share_a_group():
    g = near_duplicate_groups(_pair(0.97))
    assert _same(g, 0, 1)


def test_rows_at_090_are_apart():
    g = near_duplicate_groups(_pair(0.90))
    assert not _same(g, 0, 1)


def test_groups_are_transitive_and_deterministic():
    # a~b and b~c at cosine 0.97, a and c only about 0.88: still one component.
    t = np.arccos(0.97)
    X = np.array([[np.cos(k * t), np.sin(k * t)] for k in range(3)] + [[-1.0, 0.0]])
    assert X[0] @ X[2] < 0.95
    g = near_duplicate_groups(X)
    assert _same(g, 0, 1) and _same(g, 1, 2) and not _same(g, 0, 3)
    assert np.array_equal(g, near_duplicate_groups(X.copy()))


def test_campaign_groups_merge_by_distance_and_ties():
    X = np.array([[1.0, 0.0], [0.8, 0.6], [-1.0, 0.0], [0.0, -1.0]])
    # rows 0 and 1: cosine 0.8, distance 0.2, within 0.25. Rows 2 and 3 are far apart.
    g = campaign_groups(X, 0.25, [])
    assert _same(g, 0, 1) and not _same(g, 2, 3) and not _same(g, 0, 2)
    g = campaign_groups(X, 0.25, [(2, 3)])
    assert _same(g, 2, 3) and not _same(g, 0, 2)


def _old_components(X, adjacency_of):
    from scipy.sparse import csr_matrix
    from scipy.sparse.csgraph import connected_components
    Xn = X / np.linalg.norm(X, axis=1, keepdims=True)
    return connected_components(csr_matrix(adjacency_of(Xn @ Xn.T)), directed=False)[1]


def test_float32_components_match_the_float64_behaviour():
    rng = np.random.default_rng(0)
    centres = rng.normal(size=(6, 32))
    X = np.vstack([c + rng.normal(scale=s, size=(5, 32)) for c in centres for s in (0.05, 0.6)])
    old = _old_components(X, lambda S: S >= 0.95)
    assert len(np.unique(old)) not in (1, len(X))  # the set has both joined and lone rows
    assert np.array_equal(near_duplicate_groups(X), old)
    old = _old_components(X, lambda S: (1.0 - S) <= 0.25)
    assert np.array_equal(campaign_groups(X, 0.25, []), old)
