import json
from functools import partial

import numpy as np
import pytest

import tools.learning_curve as lc
from tests.test_training_gate import FOLDERS, _centroid_recipe, _data
from tools.learning_curve import aggregate_draws, curve_summary, run_curve, subsample_groups
from training.gate import _merge_groups, head_class_counts
from training.groups import campaign_groups, near_duplicate_groups

KEYS = {"fraction", "rows", "groups", "accuracy", "macro_f1", "dcs", "dcs_wilson", "ece",
        "campaign_dcs", "high_precision", "high_n", "checks_passed", "subsample_seed"}
AGG_KEYS = {"fraction", "n_draws", "n_feasible", "rows", "groups", "accuracy", "accuracy_range",
            "dcs", "dcs_range", "campaign_dcs", "campaign_dcs_range", "draws"}


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


def _short_values_only(row):
    for k, v in row.items():
        assert len(k) < 20
        assert not isinstance(v, str) or v in FOLDERS or len(v) < 20


def test_run_curve_rows_are_counts_and_rates_only_and_infeasible_is_reported():
    X, folders, dup, camp = _data(n_per=40)
    rows = run_curve(X, folders, dup, camp, [0.1, 0.75, 1.0], seeds=[0, 1, 2],
                     recipe=_stub(), baseline_recipe=_stub(), subsample_seeds=[0, 1, 2])
    assert [r["fraction"] for r in rows] == [0.1, 0.75, 1.0]
    low = rows[0]  # about 4 mails per folder in every draw: under the 8-per-class floor
    sub = subsample_groups(np.unique(dup, return_inverse=True)[1], 0.1, 0)
    assert min(n for ns in head_class_counts(folders[sub]).values() for n in ns) < 8
    assert low["infeasible"] is True and "accuracy" not in low
    assert (low["n_feasible"], low["n_draws"]) == (0, 3)
    for r in rows[1:]:
        assert AGG_KEYS <= set(r) and not r.get("infeasible")
        assert (r["n_feasible"], r["n_draws"]) == (3, 3)
        assert [d["subsample_seed"] for d in r["draws"]] == [0, 1, 2]
        for d in r["draws"]:
            assert KEYS <= set(d) and len(d["dcs_wilson"]) == 2
            _short_values_only(d)
        for k in ("accuracy", "dcs", "campaign_dcs"):
            lo, hi = r[f"{k}_range"]
            assert lo <= r[k] <= hi
            assert r[k] == np.mean([d[k] for d in r["draws"]])
        _short_values_only({k: v for k, v in r.items() if k != "draws"})
    full = rows[2]
    assert all(d["rows"] == len(X) for d in full["draws"])  # every draw of 1.0 is the whole set
    assert full["accuracy_range"][0] == full["accuracy_range"][1]
    assert full["groups"] > rows[1]["groups"]


def test_one_subsample_seed_keeps_the_single_draw_curve():
    X, folders, dup, camp = _data(n_per=40)
    (row,) = run_curve(X, folders, dup, camp, [0.75], seeds=[0], recipe=_stub(),
                       baseline_recipe=_stub(), subsample_seeds=[0])
    (draw,) = row["draws"]
    assert row["n_draws"] == row["n_feasible"] == 1
    assert row["accuracy"] == draw["accuracy"] and row["accuracy_range"] == [draw["accuracy"]] * 2


def test_a_fraction_is_infeasible_only_when_every_draw_is():
    def draw(seed, acc=None):
        if acc is None:
            return {"subsample_seed": seed, "rows": 10, "infeasible": True, "min_head_samples": 3}
        return {"subsample_seed": seed, "rows": 100, "groups": 20, "accuracy": acc, "dcs": 0.1,
                "campaign_dcs": 0.2}
    some = aggregate_draws(0.5, [draw(0), draw(1, 0.8), draw(2, 0.9)])
    assert not some.get("infeasible") and (some["n_feasible"], some["n_draws"]) == (2, 3)
    assert some["accuracy"] == pytest.approx(0.85) and some["accuracy_range"] == [0.8, 0.9]
    assert some["rows"] == 100  # feasible draws only
    none = aggregate_draws(0.25, [draw(0), draw(1)])
    assert none["infeasible"] is True and (none["n_feasible"], none["n_draws"]) == (0, 2)
    assert "accuracy" not in none


def test_main_prints_the_independent_group_count_and_defaults_to_three_draws(
        tmp_path, monkeypatch, capsys):
    X, folders, dup, camp = _data(n_per=10)
    path = tmp_path / "d.npz"
    np.savez(path, embeddings=X, embeddings_tokens=X, folders=folders)
    calls = {}

    def fake_run_curve(X, folders, dup, camp, fractions, **kw):
        calls.update(kw)
        return []

    monkeypatch.setattr(lc, "run_curve", fake_run_curve)
    lc.main(["--dataset", str(path), "--out", str(tmp_path / "o.json")])
    groups = len(np.unique(_merge_groups(near_duplicate_groups(X, 0.95),
                                         campaign_groups(X, 0.25, []))))
    out = capsys.readouterr().out
    assert f"INDEPENDENT GROUPS (near-duplicate + campaign, merged): {groups}" in out
    assert calls["subsample_seeds"] == [0, 1, 2]
    assert json.loads((tmp_path / "o.json").read_text())["independent_groups"] == groups
    lc.main(["--dataset", str(path), "--out", str(tmp_path / "o.json"), "--subsample-seeds", "0"])
    assert calls["subsample_seeds"] == [0]


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
