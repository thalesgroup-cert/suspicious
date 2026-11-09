"""Print the confidence_ai distribution before and after calibration (spec Risks).

usage: python tools/confidence_shift.py --dataset <npz> [--form tokens|words90] [--seeds 0,1,2]

The dataset is the .npz of tools/dataset_to_npz.py. Both sides are held-out predictions on the
same grouped folds: near-duplicate groups on the first-128 `embeddings`, as the gate uses.

Before: version 0's recipe (`legacy_recipe`) retrained on the first-128 embeddings, uncalibrated
(the hierarchy probabilities with the smoothing undone). It is not the shipped version 0 weights,
which have seen the dataset's mails.
After: the retrain recipe (`candidate_recipe`) on the chunk-mean embeddings, each component
calibrated on the other calibration half, then blended.

Each row goes through mail_analysis.getMainClassificationInfo and the connector's rounding. For
each side the tool prints the confidence_ai quantiles, its counts per band of 10 and the class
counts with the Inconclusive share. It prints counts and quantiles only, no mail text, and asserts
no value. Nothing in training/ or inference_server/ imports this file.
"""
import argparse
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mail_analysis import getMainClassificationInfo  # noqa: E402
from training.gate import (  # noqa: E402
    _cross_fit, calibrate_halves, candidate_recipe, legacy_recipe,
)
from training.groups import near_duplicate_groups  # noqa: E402
from training.recipe import EPS, _softmax, main_class  # noqa: E402

CLASSES = ("SAFE", "UNWANTED", "DANGEROUS", "INCONCLUSIVE")
QUANTILES = (0, 10, 25, 50, 75, 90, 100)


def _confidence_ai(probs):
    """(confidence_ai as the connector stores it, class) per row."""
    infos = [getMainClassificationInfo(p) for p in probs]
    return (np.array([round(i["confidence"] * 100) for i in infos]),
            [i["classification"] for i in infos])


def _print(name, probs):
    conf, classes = _confidence_ai(probs)
    q = np.percentile(conf, QUANTILES)
    print(f"{name} confidence_ai quantiles "
          + " ".join(f"p{k}={v:.0f}" for k, v in zip(QUANTILES, q)))
    hist = np.histogram(conf, bins=range(0, 101, 10))[0]
    print(f"{name} confidence_ai per 10 " + " ".join(str(int(n)) for n in hist))
    counts = {c: classes.count(c) for c in CLASSES}
    print(f"{name} classes " + " ".join(f"{c}={n}" for c, n in counts.items())
          + f" (Inconclusive {counts['INCONCLUSIVE'] / len(classes):.1%})")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, usage=argparse.SUPPRESS,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--form", choices=("tokens", "words90"), default="tokens")
    ap.add_argument("--seeds", default="0,1,2")
    args = ap.parse_args(argv)
    with np.load(args.dataset, allow_pickle=False) as d:
        first128, X, folders = d["embeddings"], d[f"embeddings_{args.form}"], d["folders"]
    seeds = [int(s) for s in args.seeds.split(",")]
    labels = np.array([main_class(f) for f in folders])
    groups = near_duplicate_groups(first128, 0.95)
    # same seeds and groups give the same folds for both sides (folds depend on rows, not X)
    (before,), _, _ = _cross_fit((legacy_recipe,), first128, folders, groups, seeds)
    (after,), _, _ = _cross_fit((candidate_recipe,), X, folders, groups, seeds)
    print(f"rows {len(folders)} seeds {seeds} (pooled over seeds)")
    # the recipe's logits are of the smoothed hierarchy: undo the smoothing for version 0's raw one
    raw = [(_softmax(z["hierarchy"]) - EPS / 3) / (1 - EPS) for z in before]
    _print("before", np.clip(np.vstack(raw), 0, 1))
    _print("after", np.vstack([calibrate_halves(z, labels, groups, seed=s)[0]
                               for z, s in zip(after, seeds)]))


if __name__ == "__main__":
    main()
