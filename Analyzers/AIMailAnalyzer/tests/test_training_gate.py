import builtins
import json
import math
from dataclasses import asdict
from functools import partial

import numpy as np
import pytest

from training import gate
from training.gate import (
    CHECKS, build_checks, calibrate_halves, candidate_recipe, ece, head_class_counts, legacy_recipe,
    run_gate, wilson,
)
from training.recipe import HEADS

FOLDERS = (
    "0_LEGIT_INTERNAL_COMMUNICATION", "0_LEGIT_EXTERNAL_COMMUNICATION", "1_SPAM", "1_NEWSLETTER",
    "2_CLASSIC_PHISHING", "2_CLONE_PHISHING", "2_BLACKMAILING_PHISHING", "2_WHALING_PHISHING",
)
Z = 1.96


# --- Wilson and ECE --------------------------------------------------------------------------

def _wilson_by_hand(k, n, z=Z):
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z / (1 + z * z / n) * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return centre - half, centre + half


def test_wilson_matches_reference_values_and_stays_in_unit_interval():
    # 0 of 10: lower 0, upper z^2 / (n + z^2) = 3.8416 / 13.8416.
    lo, hi = wilson(0, 10)
    assert lo == pytest.approx(0.0, abs=1e-12) and hi == pytest.approx(3.8416 / 13.8416, abs=1e-9)
    assert hi == pytest.approx(0.27754, abs=1e-5)
    lo, hi = wilson(10, 10)
    assert lo == pytest.approx(10 / 13.8416, abs=1e-9) and hi == pytest.approx(1.0, abs=1e-12)
    assert lo == pytest.approx(0.72246, abs=1e-5)
    for k, n in ((0, 10), (10, 10), (5, 10), (3, 17), (1, 1)):
        lo, hi = wilson(k, n)
        assert 0.0 <= lo <= hi <= 1.0
        assert (lo, hi) == pytest.approx(_wilson_by_hand(k, n), abs=1e-12)
    assert wilson(5, 10) == pytest.approx((0.23659, 0.76341), abs=1e-5)
    assert wilson(0, 0) == (0.0, 1.0)


def test_ece_is_zero_when_calibrated_and_measures_over_confidence():
    # 10 rows at 0.8 confidence, 8 right: calibrated.
    probs = np.tile([0.8, 0.1, 0.1], (10, 1))
    labels = np.array([0] * 8 + [1] * 2)
    assert ece(probs, labels) == pytest.approx(0.0, abs=1e-12)
    # Add 10 rows at 0.9 confidence, 6 right: that bin is off by 0.3 and holds half the rows.
    over = np.tile([0.05, 0.9, 0.05], (10, 1))
    over_labels = np.array([1] * 6 + [2] * 4)
    assert ece(np.vstack([probs, over]), np.r_[labels, over_labels]) == pytest.approx(0.15)


# --- the six checks ------------------------------------------------------------------------------

def _counts(n=8):
    return {"safe_suspicious": [n, n], "spam_dangerous": [n, n], "safe": [n, n],
            "unwanted": [n, n], "dangerous": [n, n, n, n]}


GOOD = dict(dangerous_safe=0.05, baseline_dangerous_safe=0.05, macro_f1=0.85,
            baseline_macro_f1=0.85, ece=0.05, head_counts=_counts(), high_precision=0.92,
            campaign_dangerous_safe=0.10, baseline_campaign_dangerous_safe=0.10)


def _failing(**change):
    checks = build_checks(**{**GOOD, **change})
    assert set(checks) == set(CHECKS)
    return {name for name, c in checks.items() if not c["passed"]}


def test_all_checks_pass_on_good_values():
    checks = build_checks(**GOOD)
    assert all(c["passed"] for c in checks.values())
    for c in checks.values():
        assert set(c) == {"passed", "value", "threshold", "detail"}


@pytest.mark.parametrize("change, failed", [
    ({"dangerous_safe": 0.0601}, {"dangerous_called_safe"}),
    ({"macro_f1": 0.8299}, {"macro_f1"}),
    ({"ece": 0.12}, {"calibration_error"}),
    ({"high_precision": 0.8999}, {"high_tier_precision"}),
    ({"campaign_dangerous_safe": 0.1101}, {"campaign_dangerous_called_safe"}),
])
def test_each_check_fails_past_its_threshold(change, failed):
    assert _failing(**change) == failed


def test_checks_hold_at_their_tolerance():
    assert not _failing(dangerous_safe=0.0599, macro_f1=0.8301, ece=0.1199, high_precision=0.90,
                        campaign_dangerous_safe=0.1099)


def test_head_check_names_the_head_and_class():
    counts = _counts()
    counts["dangerous"] = [8, 8, 7, 8]
    checks = build_checks(**{**GOOD, "head_counts": counts})
    assert not checks["head_samples"]["passed"]
    assert "dangerous" in checks["head_samples"]["detail"]
    assert "class 2" in checks["head_samples"]["detail"]


def test_head_class_counts():
    counts = head_class_counts(np.repeat(FOLDERS, 3))
    assert counts["safe_suspicious"] == [6, 18]
    assert counts["spam_dangerous"] == [6, 12]
    assert counts["dangerous"] == [3, 3, 3, 3]
    assert set(counts) == set(HEADS)


# --- calibration on held-out halves ----------------------------------------------------------

def test_calibration_never_sees_the_rows_it_scores():
    rng = np.random.default_rng(0)
    n = 60
    groups = np.repeat(np.arange(20), 3)
    labels = rng.integers(0, 3, n)
    logits = {"hierarchy": rng.normal(size=(n, 3)) * 3, "knn": rng.normal(size=(n, 3))}
    probs, temps = calibrate_halves(logits, labels, groups, seed=0)
    assert probs.shape == (n, 3) and len(temps) == 2
    for g in (0, 7, 19):
        flipped = labels.copy()
        flipped[groups == g] = (flipped[groups == g] + 1) % 3
        probs2, _ = calibrate_halves(logits, flipped, groups, seed=0)
        np.testing.assert_array_equal(probs2[groups == g], probs[groups == g])
        assert not np.array_equal(probs2, probs)  # the other half did move


# --- run_gate with stub recipes ------------------------------------------------------------------

def _data(n_per=10, dim=8, seed=0, sep=4.0):
    rng = np.random.default_rng(seed)
    centres = rng.normal(size=(len(FOLDERS), dim)) * sep
    X, folders, groups = [], [], []
    for i, f in enumerate(FOLDERS):
        for j in range(n_per):
            X.append(centres[i] + rng.normal(size=dim))
            folders.append(f)
            groups.append(i * 100 + j // 2)  # near-duplicate pairs
    groups = np.unique(groups, return_inverse=True)[1]
    campaigns = groups // 2  # each campaign joins two pairs
    return np.array(X, dtype=np.float32), np.array(folders), groups, campaigns


def _centroid_recipe(calls, name, X, folders, train_idx, test_idx, *, seed):
    """Nearest-centroid stub: fast, deterministic, trained on train_idx only."""
    calls.append((name, seed, tuple(train_idx), tuple(test_idx)))
    y = np.array([int(f[0]) for f in folders])
    cents = np.stack([X[train_idx][y[train_idx] == c].mean(0) for c in range(3)])
    d = ((X[test_idx][:, None, :] - cents[None]) ** 2).sum(-1)
    return {"hierarchy": -d / d.mean()}


def _stubs():
    calls = []
    return calls, partial(_centroid_recipe, calls, "cand"), partial(_centroid_recipe, calls, "base")


def test_run_gate_folds_keep_groups_and_baseline_gets_the_same_train_rows():
    X, folders, dup, camp = _data()
    calls, cand, base = _stubs()
    report = run_gate(X, folders, dup, camp, recipe=cand, baseline_recipe=base)
    assert report.seeds == [0, 1, 2]
    for kind, groups in (("main", dup), ("campaign", camp)):
        part = calls[:30] if kind == "main" else calls[30:]
        assert len(part) == 30  # 3 seeds x 5 folds x (candidate, baseline)
        for _, _, tr, te in part:
            assert not set(groups[list(tr)]) & set(groups[list(te)])
            assert not set(dup[list(tr)]) & set(dup[list(te)])
    cand_calls = [c[1:] for c in calls if c[0] == "cand"]
    base_calls = [c[1:] for c in calls if c[0] == "base"]
    assert cand_calls == base_calls


def test_campaign_folds_also_keep_near_duplicates_together():
    # Row 1 and 2 share a near-duplicate group, rows 0 and 1 a campaign: 0, 1, 2 stay together.
    merged = gate._merge_groups(np.array([0, 1, 1, 2]), np.array([5, 5, 6, 7]))
    assert merged[0] == merged[1] == merged[2] != merged[3]


def test_run_gate_report_contents_and_eligibility():
    X, folders, dup, camp = _data()
    _, cand, base = _stubs()
    report = run_gate(X, folders, dup, camp, recipe=cand, baseline_recipe=base)
    assert set(report.checks) == set(CHECKS)
    assert report.eligible == all(c["passed"] for c in report.checks.values())
    n = len(X)
    cm = np.array(report.confusion_matrix)
    assert cm.shape == (3, 3) and cm.sum() == 3 * n  # pooled over three repeats
    for row in report.per_class:
        assert set(row) >= {"class", "support", "recall", "recall_ci", "precision", "precision_ci"}
        assert 0.0 <= row["recall_ci"][0] <= row["recall"] <= row["recall_ci"][1] <= 1.0
    assert [t["tier"] for t in report.tiers] == ["High", "Medium", "Low"]
    assert sum(t["n"] for t in report.tiers) == 3 * n
    assert report.tier_cutoffs["medium"] == 0.60
    assert report.tier_cutoffs["high"] >= 0.60
    assert "dangerous_called_safe" in report.campaign and "fallback" in report.campaign
    assert set(report.baseline) >= {"dangerous_called_safe", "macro_f1",
                                    "campaign_dangerous_called_safe"}
    assert isinstance(report.fallback, bool)
    assert set(report.temperature_at_bound) == {"hierarchy"}
    assert report.counts["rows"] == n
    json.dumps(asdict(report))  # plain values only, no arrays and no mail data
    # Same candidate and baseline: the comparison checks pass.
    assert report.checks["dangerous_called_safe"]["passed"]
    assert report.checks["macro_f1"]["passed"]


def test_any_failed_check_makes_the_report_ineligible():
    X, folders, dup, camp = _data()
    _, cand, base = _stubs()

    def calls_dangerous_safe(X, folders, train_idx, test_idx, *, seed):
        out = cand(X, folders, train_idx, test_idx, seed=seed)["hierarchy"].copy()
        out[:, 0] = out[:, 2] + 1.0  # every Dangerous mail is now called Safe
        return {"hierarchy": out}

    report = run_gate(X, folders, dup, camp, recipe=calls_dangerous_safe, baseline_recipe=base)
    assert not report.checks["dangerous_called_safe"]["passed"]
    assert not report.checks["campaign_dangerous_called_safe"]["passed"]
    assert not report.eligible


def test_a_head_short_of_samples_fails_the_whole_candidate_without_training():
    X, folders, dup, camp = _data()
    keep = ~((folders == "2_WHALING_PHISHING") & (np.arange(len(folders)) % 10 >= 5))
    calls, cand, base = _stubs()
    report = run_gate(X[keep], folders[keep], dup[keep], camp[keep], recipe=cand,
                      baseline_recipe=base)
    assert calls == []
    assert not report.eligible
    assert "dangerous" in report.checks["head_samples"]["detail"]
    assert "class 3" in report.checks["head_samples"]["detail"]


def test_high_tier_unreachable_sets_cutoff_above_one():
    X, folders, dup, camp = _data(sep=0.0)  # no signal: precision never reaches 0.90
    _, cand, base = _stubs()
    report = run_gate(X, folders, dup, camp, recipe=cand, baseline_recipe=base)
    assert report.tier_cutoffs["high"] == 1.01
    assert not report.checks["high_tier_precision"]["passed"]


def test_falls_back_to_group_kfold_when_stratification_is_infeasible(monkeypatch):
    X, folders, dup, camp = _data()

    class Infeasible:
        def __init__(self, *a, **kw):
            pass

        def split(self, *a, **kw):
            raise ValueError("n_splits=5 cannot be greater than the number of members")

    monkeypatch.setattr(gate, "StratifiedGroupKFold", Infeasible)
    calls, cand, base = _stubs()
    report = run_gate(X, folders, dup, camp, recipe=cand, baseline_recipe=base)
    assert report.fallback is True and report.campaign["fallback"] is True
    for _, _, tr, te in calls:
        assert not set(dup[list(tr)]) & set(dup[list(te)])


def test_run_gate_is_reproducible_with_the_real_recipe():
    X, folders, dup, camp = _data(n_per=8)
    kw = dict(recipe=partial(candidate_recipe, epochs=1),
              baseline_recipe=partial(candidate_recipe, epochs=1), repeats=1)
    a = run_gate(X, folders, dup, camp, **kw)
    b = run_gate(X, folders, dup, camp, **kw)
    assert asdict(a) == asdict(b)
    assert a.seeds == [0]
    assert set(a.temperature_at_bound) == {"hierarchy", "knn"}


def test_legacy_recipe_needs_imblearn(monkeypatch):
    real_import = builtins.__import__

    def no_imblearn(name, *a, **kw):
        if name.startswith("imblearn"):
            raise ImportError(name)
        return real_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", no_imblearn)
    X, folders, _, _ = _data(n_per=8)
    with pytest.raises(RuntimeError, match="imbalanced-learn"):
        legacy_recipe(X, folders, np.arange(40), np.arange(40, 64), seed=0)


def test_gate_module_does_not_import_imblearn_at_top_level():
    src = open(gate.__file__).read()
    top = [line for line in src.splitlines() if line.startswith(("import ", "from "))]
    assert not any("imblearn" in line for line in top)
