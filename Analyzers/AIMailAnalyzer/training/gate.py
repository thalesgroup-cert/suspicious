"""The gate (spec section 5): six offline checks a candidate must pass before shadow.

Held-out protocol, as in the test bed (exp_e_combined.py, exp_a2_calibrate.py): per seed, 5-fold
StratifiedGroupKFold on the near-duplicate groups gives out-of-fold component logits; the
temperatures are fitted on a random half of the groups and applied to the other half (and the
other way round), so no row is scored by a calibration fitted on its own group. The baseline is
the active recipe retrained on the same folds (not the active weights, which may have seen the
mails). A recipe is a callable recipe(X, folders, train_idx, test_idx, *, seed) returning
{component: (len(test_idx), 3) logits}; the components are calibrated and averaged.
"""
import math
from dataclasses import dataclass, field

import numpy as np
import torch
from scipy.sparse import csr_matrix
from scipy.sparse.csgraph import connected_components
from sklearn.metrics import f1_score
from sklearn.model_selection import GroupKFold, StratifiedGroupKFold

from .recipe import (
    HEADS, NUM_OUT, Heads, Knn, _softmax, _train_head, fit_heads, fit_temperature, head_target,
    main_class, predict, temperature_at_bound,
)

N_SPLITS = 5
MIN_HEAD_SAMPLES = 8
DANGEROUS_SAFE_TOLERANCE = 0.01
MACRO_F1_TOLERANCE = 0.02
MAX_ECE = 0.12  # Ruling E6
HIGH_PRECISION = 0.90
MEDIUM_CUTOFF = 0.60
HIGH_UNREACHABLE = 1.01
CLASSES = ("Safe", "Unwanted", "Dangerous")
CHECKS = ("dangerous_called_safe", "macro_f1", "calibration_error", "head_samples",
          "high_tier_precision", "campaign_dangerous_called_safe")


# --- statistics ----------------------------------------------------------------------------------

def wilson(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval for successes out of n (Ruling E4); (0, 1) when n is 0."""
    if n == 0:
        return (0.0, 1.0)
    p = successes / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z / d * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    # At 0 and n the bounds are exactly 0 and 1; pin them against rounding.
    return (0.0 if successes == 0 else max(0.0, centre - half),
            1.0 if successes == n else min(1.0, centre + half))


def ece(probs, labels, bins: int = 15) -> float:
    """Binned calibration error (Ruling E6): equal-width bins (lo, hi] on the top-class
    probability, |confidence - accuracy| weighted by the bin's share of rows."""
    probs = np.asarray(probs)
    conf, correct = probs.max(1), probs.argmax(1) == np.asarray(labels)
    b = np.clip(np.ceil(conf * bins).astype(int) - 1, 0, bins - 1)
    return float(sum(abs(conf[m].mean() - correct[m].mean()) * m.mean()
                     for k in range(bins) if (m := b == k).any()))


def _dangerous_safe(labels, pred) -> float:
    """Share of true Dangerous mails predicted Safe."""
    return float(((labels == 2) & (pred == 0)).sum() / max((labels == 2).sum(), 1))


# --- the six checks ------------------------------------------------------------------------------

def head_class_counts(folders) -> dict:
    """{head: [rows per class]} over the whole dataset."""
    counts = {h: [0] * NUM_OUT[h] for h in HEADS}
    for f in folders:
        for h in HEADS:
            if (t := head_target(h, f)) is not None:
                counts[h][t] += 1
    return counts


def _check(passed, value, threshold, detail):
    return {"passed": bool(passed), "value": value, "threshold": threshold, "detail": detail}


def _head_check(head_counts):
    short = [f"head {h} class {c} has {n} samples" for h, ns in head_counts.items()
             for c, n in enumerate(ns) if n < MIN_HEAD_SAMPLES]
    low = min(n for ns in head_counts.values() for n in ns)
    return _check(not short, low, MIN_HEAD_SAMPLES,
                  "; ".join(short) + f" (needs {MIN_HEAD_SAMPLES})" if short
                  else f"every head has at least {MIN_HEAD_SAMPLES} samples per class")


def build_checks(*, dangerous_safe, baseline_dangerous_safe, macro_f1, baseline_macro_f1, ece,
                 head_counts, high_precision, campaign_dangerous_safe,
                 baseline_campaign_dangerous_safe) -> dict:
    ds_max = baseline_dangerous_safe + DANGEROUS_SAFE_TOLERANCE
    f1_min = baseline_macro_f1 - MACRO_F1_TOLERANCE
    camp_max = baseline_campaign_dangerous_safe + DANGEROUS_SAFE_TOLERANCE
    high_ok = high_precision is not None and high_precision >= HIGH_PRECISION
    return {
        "dangerous_called_safe": _check(
            dangerous_safe <= ds_max, dangerous_safe, ds_max,
            f"Dangerous called Safe {dangerous_safe:.4f}, baseline {baseline_dangerous_safe:.4f}"),
        "macro_f1": _check(macro_f1 >= f1_min, macro_f1, f1_min,
                           f"macro-F1 {macro_f1:.4f}, baseline {baseline_macro_f1:.4f}"),
        "calibration_error": _check(ece < MAX_ECE, ece, MAX_ECE,
                                    f"binned calibration error {ece:.4f}, must be below {MAX_ECE}"),
        "head_samples": _head_check(head_counts),
        "high_tier_precision": _check(
            high_ok, high_precision, HIGH_PRECISION,
            "High tier unreachable: no cutoff reaches the precision" if high_precision is None
            else f"High tier precision {high_precision:.4f}"),
        "campaign_dangerous_called_safe": _check(
            campaign_dangerous_safe <= camp_max, campaign_dangerous_safe, camp_max,
            f"on held-out campaigns, Dangerous called Safe {campaign_dangerous_safe:.4f}, "
            f"baseline {baseline_campaign_dangerous_safe:.4f}"),
    }


# --- recipes -------------------------------------------------------------------------------------

def candidate_recipe(X, folders, train_idx, test_idx, *, seed, epochs=30, threads=2) -> dict:
    """The retrain recipe (training/recipe.py): head hierarchy and 5-NN vote logits."""
    heads = fit_heads(X[train_idx], folders[train_idx], seed=seed, epochs=epochs, threads=threads)
    return predict(heads, Knn.build(X[train_idx], folders[train_idx]), X[test_idx]).logits


def _smote_ros(SMOTE, RandomOverSampler, X, y):
    """The test bed's lib_spike.smote_ros, itself verbatim from the legacy utils.smote_ros: every
    class scaled by 1.25 with SMOTE then by 1.10 with random oversampling, random_state 42."""
    counts = np.bincount(y)
    present = np.flatnonzero(counts)
    k = min(5, max(1, int(counts[present].min()) - 1))
    Xs, ys = SMOTE(sampling_strategy={int(c): int(counts[c] * 1.25) for c in present},
                   k_neighbors=k, random_state=42).fit_resample(X, y)
    after = np.bincount(ys)
    return RandomOverSampler(sampling_strategy={int(c): int(after[c] * 1.10) for c in present},
                             random_state=42).fit_resample(Xs, ys)


def legacy_recipe(X, folders, train_idx, test_idx, *, seed, epochs=30, threads=2) -> dict:
    """Version 0's recipe (the test bed's "asis"): SMOTE + random oversampling then class weights
    per head, head hierarchy only (no neighbour vote). A head that SMOTE cannot resample trains
    without it, as the legacy code did. Use it as baseline_recipe while version 0 is active.
    Needs imbalanced-learn, which the inference image does not ship."""
    try:
        from imblearn.over_sampling import SMOTE, RandomOverSampler
    except ImportError as exc:
        raise RuntimeError("legacy_recipe needs imbalanced-learn (imblearn), which is not "
                           "installed; install it to reproduce version 0's baseline") from exc
    Xtr, ftr = X[train_idx], folders[train_idx]
    previous = torch.get_num_threads()
    torch.set_num_threads(threads)
    try:
        models = {}
        for head in HEADS:
            rows = [(i, t) for i, f in enumerate(ftr) if (t := head_target(head, f)) is not None]
            idx, y = zip(*rows)
            Xh, yh = Xtr[list(idx)], np.array(y)
            try:
                Xh, yh = _smote_ros(SMOTE, RandomOverSampler, Xh, yh)
            except ValueError:
                pass
            models[head] = _train_head(Xh, yh, NUM_OUT[head], seed, epochs)
    finally:
        torch.set_num_threads(previous)
    logits = predict(Heads(models, X.shape[1]), Knn.build(Xtr, ftr), X[test_idx]).logits
    return {"hierarchy": logits["hierarchy"]}


# --- held-out predictions ------------------------------------------------------------------------

def _merge_groups(a, b) -> np.ndarray:
    """Component id per row joining rows that share a group in a or in b."""
    a = np.unique(a, return_inverse=True)[1]
    b = np.unique(b, return_inverse=True)[1] + a.max() + 1
    n = len(a)
    size = n + b.max() + 1
    rows, cols = np.r_[np.arange(n), np.arange(n)], n + np.r_[a, b]
    graph = csr_matrix((np.ones(2 * n), (rows, cols)), shape=(size, size))
    return connected_components(graph, directed=False)[1][:n]


def _folds(X, folders, groups, seed):
    """5 grouped folds; GroupKFold when stratified folds are infeasible (error or empty fold)."""
    try:
        folds = list(StratifiedGroupKFold(N_SPLITS, shuffle=True, random_state=seed)
                     .split(X, folders, groups))
        if all(len(te) for _, te in folds):
            return folds, False
    except ValueError:
        pass
    return list(GroupKFold(N_SPLITS, shuffle=True, random_state=seed).split(X, folders, groups)), True


def _cross_fit(recipes, X, folders, groups, seeds):
    """Out-of-fold component logits, [recipe][seed] -> {component: (n, 3)}; all recipes get the
    same folds."""
    out = [[{} for _ in seeds] for _ in recipes]
    fallback = False
    for s, seed in enumerate(seeds):
        folds, fb = _folds(X, folders, groups, seed)
        fallback |= fb
        for tr, te in folds:
            for r, recipe in enumerate(recipes):
                for c, z in recipe(X, folders, tr, te, seed=seed).items():
                    out[r][s].setdefault(c, np.zeros((len(X), 3)))[te] = z
    return out, fallback


def calibrate_halves(logits: dict, labels, groups, *, seed) -> tuple[np.ndarray, list]:
    """Calibrated blend of the components: temperatures fitted on a random half of the groups
    score the other half, and the other way round. Returns (probs, [temperatures per half])."""
    labels = np.asarray(labels)
    ug = np.unique(groups)
    in_a = np.isin(groups, np.random.default_rng(seed).choice(ug, len(ug) // 2, replace=False))
    probs, temps = np.zeros((len(labels), 3)), []
    for fit, ev in ((in_a, ~in_a), (~in_a, in_a)):
        t = {c: fit_temperature(z[fit], labels[fit]) for c, z in logits.items()}
        probs[ev] = np.mean([_softmax(z[ev] / t[c]) for c, z in logits.items()], axis=0)
        temps.append(t)
    return probs, temps


def _metrics(probs, labels):
    pred = probs.argmax(1)
    return {"dangerous_called_safe": _dangerous_safe(labels, pred),
            "macro_f1": float(f1_score(labels, pred, labels=[0, 1, 2], average="macro",
                                       zero_division=0)),
            "ece": ece(probs, labels)}


def _mean(rows, key):
    return float(np.mean([r[key] for r in rows]))


def _high_cutoff(conf, correct):
    """Smallest cutoff at or above Medium whose rows reach HIGH_PRECISION; (1.01, None) if none."""
    # ponytail: O(n^2) scan over unique confidences, fine for a few thousand pooled rows.
    for t in np.unique(conf[conf >= MEDIUM_CUTOFF]):
        precision = correct[conf >= t].mean()
        if precision >= HIGH_PRECISION:
            return float(t), float(precision)
    return HIGH_UNREACHABLE, None


# --- the gate ------------------------------------------------------------------------------------

@dataclass
class GateReport:
    checks: dict
    seeds: list
    counts: dict  # row, class and head counts only; no mail data
    per_class: list = field(default_factory=list)
    confusion_matrix: list = field(default_factory=list)  # [true][pred], pooled over seeds
    tiers: list = field(default_factory=list)
    tier_cutoffs: dict = field(default_factory=dict)
    campaign: dict = field(default_factory=dict)
    baseline: dict = field(default_factory=dict)
    candidate: dict = field(default_factory=dict)
    fallback: bool = False  # GroupKFold used because stratified folds were infeasible
    temperature_at_bound: dict = field(default_factory=dict)

    @property
    def eligible(self) -> bool:
        return all(c["passed"] for c in self.checks.values())


def run_gate(X, folders, groups_dup, groups_campaign, *, baseline_recipe, recipe=candidate_recipe,
             repeats: int = 3, seed0: int = 0) -> GateReport:
    """Run the six checks (spec section 5) over `repeats` seeds of 5 grouped folds (Ruling E7).
    baseline_recipe is the active version's recipe (legacy_recipe for version 0); both recipes
    are trained on the same train rows. Metrics are averaged over seeds; intervals, the confusion
    matrix and the tiers use counts pooled over seeds."""
    X, folders = np.asarray(X, dtype=np.float32), np.asarray(folders)
    groups_dup = np.asarray(groups_dup)
    labels = np.array([main_class(f) for f in folders])
    seeds = [seed0 + r for r in range(repeats)]
    head_counts = head_class_counts(folders)
    counts = {"rows": len(X), "classes": np.bincount(labels, minlength=3).tolist(),
              "heads": head_counts}

    head = _head_check(head_counts)
    if not head["passed"]:  # a head that cannot train fails the whole candidate
        checks = {name: _check(False, None, None, "not run: " + head["detail"]) for name in CHECKS}
        checks["head_samples"] = head
        return GateReport(checks=checks, seeds=seeds, counts=counts)

    def held_out(groups):
        (cand, base), fallback = _cross_fit((recipe, baseline_recipe), X, folders, groups, seeds)
        cal = [calibrate_halves(z, labels, groups, seed=seed) for z, seed in zip(cand, seeds)]
        base_probs = [calibrate_halves(z, labels, groups, seed=seed)[0]
                      for z, seed in zip(base, seeds)]
        return cal, base_probs, fallback

    cal, base_probs, fallback = held_out(groups_dup)
    probs = [p for p, _ in cal]
    cand_m = [_metrics(p, labels) for p in probs]
    base_m = [_metrics(p, labels) for p in base_probs]

    merged = _merge_groups(groups_dup, np.asarray(groups_campaign))
    camp_cal, camp_base, camp_fallback = held_out(merged)
    camp_ds = float(np.mean([_dangerous_safe(labels, p.argmax(1)) for p, _ in camp_cal]))
    camp_base_ds = float(np.mean([_dangerous_safe(labels, p.argmax(1)) for p in camp_base]))

    pooled, y = np.vstack(probs), np.tile(labels, len(seeds))
    pred, conf = pooled.argmax(1), pooled.max(1)
    correct = pred == y
    cm = np.zeros((3, 3), dtype=int)
    np.add.at(cm, (y, pred), 1)
    per_class = []
    for c, name in enumerate(CLASSES):
        support, called = int(cm[c].sum()), int(cm[:, c].sum())
        hit = int(cm[c, c])
        per_class.append({"class": name, "support": support,
                          "recall": hit / support if support else 0.0,
                          "recall_ci": list(wilson(hit, support)),
                          "precision": hit / called if called else 0.0,
                          "precision_ci": list(wilson(hit, called))})

    high, high_precision = _high_cutoff(conf, correct)
    tiers = []
    for name, m in (("High", conf >= high), ("Medium", (conf >= MEDIUM_CUTOFF) & (conf < high)),
                    ("Low", conf < MEDIUM_CUTOFF)):
        n, right = int(m.sum()), int(correct[m].sum())
        tiers.append({"tier": name, "n": n, "correct": right,
                      "precision": right / n if n else 0.0, "precision_ci": list(wilson(right, n)),
                      "dangerous_called_safe": int(((y == 2) & (pred == 0) & m).sum())})

    candidate = {k: _mean(cand_m, k) for k in cand_m[0]}
    baseline = {k: _mean(base_m, k) for k in base_m[0]}
    baseline["campaign_dangerous_called_safe"] = camp_base_ds
    checks = build_checks(
        dangerous_safe=candidate["dangerous_called_safe"],
        baseline_dangerous_safe=baseline["dangerous_called_safe"],
        macro_f1=candidate["macro_f1"], baseline_macro_f1=baseline["macro_f1"],
        ece=candidate["ece"], head_counts=head_counts, high_precision=high_precision,
        campaign_dangerous_safe=camp_ds, baseline_campaign_dangerous_safe=camp_base_ds)
    temps = [t for _, ts in cal for t in ts]
    return GateReport(
        checks=checks, seeds=seeds, counts=counts, per_class=per_class,
        confusion_matrix=cm.tolist(), tiers=tiers,
        tier_cutoffs={"high": high, "medium": MEDIUM_CUTOFF},
        campaign={"dangerous_called_safe": camp_ds, "baseline_dangerous_called_safe": camp_base_ds,
                  "groups": int(len(np.unique(merged))), "fallback": camp_fallback},
        baseline=baseline, candidate=candidate, fallback=fallback,
        temperature_at_bound={c: any(temperature_at_bound(t[c]) for t in temps) for c in temps[0]})
