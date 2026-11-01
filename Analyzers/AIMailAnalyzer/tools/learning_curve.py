"""Learning curve: how the gate metrics move with the number of independent groups.

    python tools/learning_curve.py --dataset <npz> --form tokens|words90 \
        --fractions 0.25,0.5,0.75,1.0 --seeds 0,1,2 --out <json>

The dataset is the .npz of tools/dataset_to_npz.py. Groups are near-duplicate groups merged with
campaign groups (both computed on the first-128 `embeddings`, Ruling E18), so a subsample keeps
both groupings whole. For one subsample seed the group ids are shuffled once and a fraction takes
a prefix, so the sets are nested. The gate seeds (--seeds) are separate from --subsample-seed:
every fraction runs the gate on one subsample, so the curve carries subsample noise as well as
gate noise. Only counts and rates are printed or written; no mail text. Nothing in training/ or
inference_server/ imports this file.
"""
import argparse
import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from training.gate import (  # noqa: E402
    MIN_HEAD_SAMPLES, _merge_groups, candidate_recipe, head_class_counts, legacy_recipe, run_gate,
    wilson,
)

IMPROVE_ACCURACY = 0.01
IMPROVE_DCS = 0.005


def subsample_groups(groups, fraction, seed):
    """Sorted row indices of the first round(fraction * G) groups of a seeded shuffle."""
    groups = np.asarray(groups)
    ids = np.unique(groups)
    order = np.random.default_rng(seed).permutation(ids)
    keep = order[: max(1, round(fraction * len(ids)))]
    return np.flatnonzero(np.isin(groups, keep))


def _row(fraction, idx, merged, report):
    cm = np.array(report.confusion_matrix)
    R = report.pooled_repeats
    high = report.high_tier
    return {
        "fraction": fraction, "rows": int(len(idx)), "groups": int(len(np.unique(merged[idx]))),
        "accuracy": float(np.trace(cm) / cm.sum()), "macro_f1": report.candidate["macro_f1"],
        "dcs": report.candidate["dangerous_called_safe"],
        "dcs_wilson": [float(v) for v in wilson(cm[2, 0] / R, cm[2].sum() / R)],
        "ece": report.candidate["ece"],
        "campaign_dcs": report.campaign["dangerous_called_safe"],
        "high_precision": high["correct"] / high["n"] if high["n"] else None,
        "high_n": high["n"], "checks_passed": sum(c["passed"] for c in report.checks.values()),
    }


def run_curve(X, folders, dup, camp, fractions, *, seeds, recipe=candidate_recipe,
              baseline_recipe=legacy_recipe, subsample_seed=0):
    X, folders = np.asarray(X), np.asarray(folders)
    merged = _merge_groups(np.asarray(dup), np.asarray(camp))
    rows = []
    for f in fractions:
        idx = subsample_groups(merged, f, subsample_seed)
        low = min(n for ns in head_class_counts(folders[idx]).values() for n in ns)
        if low < MIN_HEAD_SAMPLES:  # check 4 would fail and nothing would train
            rows.append({"fraction": f, "rows": int(len(idx)), "infeasible": True,
                         "min_head_samples": low})
            continue
        report = run_gate(X[idx], folders[idx], np.asarray(dup)[idx], np.asarray(camp)[idx],
                          recipe=recipe, baseline_recipe=baseline_recipe,
                          repeats=len(seeds), seed0=min(seeds))
        rows.append(_row(f, idx, merged, report))
    return rows


def curve_summary(rows):
    """Slopes between consecutive feasible fractions, and whether the last step still improves."""
    ok = [r for r in rows if "accuracy" in r]
    steps = []
    for a, b in zip(ok, ok[1:]):
        per100 = 100 / (b["groups"] - a["groups"])
        steps.append({
            "from": a["fraction"], "to": b["fraction"],
            "accuracy_per_100_groups": round((b["accuracy"] - a["accuracy"]) * per100, 6),
            "dcs_per_100_groups": round((b["dcs"] - a["dcs"]) * per100, 6),
            "accuracy_gain": b["accuracy"] - a["accuracy"], "dcs_change": b["dcs"] - a["dcs"]})
    last = steps[-1] if steps else None
    improving = None if last is None else bool(
        last["accuracy_gain"] > IMPROVE_ACCURACY or -last["dcs_change"] > IMPROVE_DCS)
    return {"steps": steps, "still_improving": improving}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--form", choices=("tokens", "words90"), default="tokens")
    ap.add_argument("--fractions", default="0.25,0.5,0.75,1.0")
    ap.add_argument("--seeds", default="0,1,2", help="gate seeds, consecutive")
    ap.add_argument("--subsample-seed", type=int, default=0)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)

    from training.groups import campaign_groups, near_duplicate_groups

    with np.load(args.dataset, allow_pickle=False) as d:
        X, folders, first128 = d[f"embeddings_{args.form}"], d["folders"], d["embeddings"]
    dup = near_duplicate_groups(first128, 0.95)
    camp = campaign_groups(first128, 0.25, [])
    seeds = [int(s) for s in args.seeds.split(",")]
    assert seeds == list(range(seeds[0], seeds[0] + len(seeds))), "seeds must be consecutive"
    try:
        import imblearn  # noqa: F401
        baseline, baseline_name = legacy_recipe, "legacy_recipe"
    except ImportError:
        # not evaluated: the baseline is the candidate itself, so checks 1, 2 and 6 are vacuous
        baseline, baseline_name = candidate_recipe, "not evaluated (imbalanced-learn missing)"
    fractions = [float(f) for f in args.fractions.split(",")]
    rows = run_curve(X, folders, dup, camp, fractions, seeds=seeds, baseline_recipe=baseline,
                     subsample_seed=args.subsample_seed)
    out = {"form": args.form, "baseline": baseline_name, "seeds": seeds,
           "subsample_seed": args.subsample_seed, "rows": rows, "summary": curve_summary(rows)}
    Path(args.out).write_text(json.dumps(out, indent=1, default=float))
    for r in rows:
        print(" ".join(f"{k}={v:.4g}" if isinstance(v, float) else f"{k}={v}"
                       for k, v in r.items()))
    print("still_improving", out["summary"]["still_improving"])


if __name__ == "__main__":
    main()
