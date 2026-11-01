from functools import partial

import numpy as np

from tests.test_training_gate import FOLDERS, _centroid_recipe, _data
from tools.learning_curve import curve_summary, run_curve, subsample_groups
from training.gate import head_class_counts

KEYS = {"fraction", "rows", "groups", "accuracy", "macro_f1", "dcs", "dcs_wilson", "ece",
        "campaign_dcs", "high_precision", "high_n", "checks_passed"}


def _stub():
    return partial(_centroid_recipe, [], "x")


def test_subsample_keeps_whole_groups_is_deterministic_and_nested():
    groups = np.repeat(np.arange(40), 3)
    prev = set()
    for f in (0.25, 0.5, 0.75, 1.0):
        idx = subsample_groups(groups, f, seed=1)
        kept = set(groups[idx])
        assert len(kept) == round(f * 40)
        for g in kept:  # no group is split
            assert (groups == g).sum() == (groups[idx] == g).sum()
        assert np.array_equal(idx, subsample_groups(groups, f, seed=1))
        assert prev <= kept  # nested
        prev = kept
    assert not np.array_equal(subsample_groups(groups, 0.5, 1), subsample_groups(groups, 0.5, 2))


def test_run_curve_rows_are_counts_and_rates_only_and_infeasible_is_reported():
    X, folders, dup, camp = _data(n_per=40)
    rows = run_curve(X, folders, dup, camp, [0.1, 0.75, 1.0], seeds=[0, 1, 2],
                     recipe=_stub(), baseline_recipe=_stub())
    assert [r["fraction"] for r in rows] == [0.1, 0.75, 1.0]
    low = rows[0]  # about 4 mails per folder: under the 8-per-class floor on some head
    sub = subsample_groups(np.unique(dup, return_inverse=True)[1], 0.1, 0)
    assert min(n for ns in head_class_counts(folders[sub]).values() for n in ns) < 8
    assert low.get("infeasible") is True and "accuracy" not in low
    for r in rows[1:]:
        assert KEYS <= set(r) and not r.get("infeasible")
        assert 0 <= r["accuracy"] <= 1 and len(r["dcs_wilson"]) == 2
    assert rows[2]["rows"] == len(X) and rows[2]["groups"] > rows[1]["groups"]
    for r in rows:
        for k, v in r.items():
            assert len(k) < 20
            assert not isinstance(v, str) or v in FOLDERS or len(v) < 20


def test_curve_summary_slopes_and_still_improving_flag():
    def row(f, g, acc, dcs):
        return {"fraction": f, "groups": g, "accuracy": acc, "dcs": dcs}
    rows = [row(0.5, 100, 0.80, 0.08), row(1.0, 200, 0.83, 0.07)]
    s = curve_summary(rows)
    assert s["steps"][0]["accuracy_per_100_groups"] == 0.03
    assert s["still_improving"] is True
    flat = [row(0.5, 100, 0.83, 0.07), row(1.0, 200, 0.835, 0.068)]
    assert curve_summary(flat)["still_improving"] is False
    assert curve_summary([row(1.0, 200, 0.8, 0.07)])["still_improving"] is None
