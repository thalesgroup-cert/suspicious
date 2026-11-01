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
