"""Golden (held-out) evaluation set for the AIMailAnalyzer retrain pipeline.

Why this exists: main_retrainmodels.py re-splits train/test randomly out of
the *cumulative* dataset.pkl every cycle. As that dataset grows, the random
20% test slice is different content each time - so "F1 went from 0.93 to
0.95" between two cycles isn't a real improvement signal, it's two different
exams. The golden set fixes a small, stratified, NEVER-retrained-on subset
so every cycle's model gets scored against the exact same held-out mails,
making the trend actually mean something.

Sizing (see conversation notes): stratified per taxonomy folder, with a
per-class floor (so rare classes like BLACKMAILING_PHISHING aren't invisible
in the benchmark) and a global cap (so this stays cheap once a production
mailbox has thousands of mails) - see build_golden_set()'s defaults.

Content is strictly additive: once a hash is in the golden set it is never
removed and never used for training again, ever. Growing the benchmark
(--expand) only adds new hashes on top of the existing ones, so scores from
old cycles stay comparable to new ones within the same golden-set version;
the version bumps on every --expand so it's clear in the data when the
benchmark itself changed.

Usage:
    python golden_set.py --create                  # first cut, from data_export/dataset.pkl
    python golden_set.py --expand 20                # add up to 20 more stratified samples
    python golden_set.py --show                     # print current composition
"""
import argparse
import json
import os
import random
from collections import Counter
from datetime import datetime, timezone

import pandas as pd

DATASET_PATH = os.environ.get("DATASET_DIR", "data_export") + "/dataset.pkl"
GOLDEN_SET_PATH = "golden_set.json"

DEFAULT_MIN_PER_CLASS = 2
DEFAULT_PCT = 0.20
DEFAULT_CAP = 40
RANDOM_STATE = 42


def _load_dataset(dataset_path: str = DATASET_PATH) -> pd.DataFrame:
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(
            f"{dataset_path} n'existe pas - lancez generator_dataset.py d'abord."
        )
    return pd.read_pickle(dataset_path)


def load_golden_set(path: str = GOLDEN_SET_PATH) -> dict:
    if not os.path.exists(path):
        return {"version": 0, "hashes": []}
    with open(path, "r") as f:
        return json.load(f)


def load_golden_hashes(path: str = GOLDEN_SET_PATH) -> set:
    """What pre_process() actually needs: the set of hashes to exclude from
    train/test everywhere. Empty set (not an error) if no golden set exists
    yet - callers should treat "no golden set" as "nothing held out"."""
    return set(load_golden_set(path).get("hashes", []))


def _select_stratified(
    df: pd.DataFrame,
    already_selected: set,
    min_per_class: int,
    pct: float,
    cap: int,
    random_state: int,
) -> list:
    """Pick new hashes, stratified by folder, respecting the per-class floor,
    the global cap, and never taking a class down to zero remaining
    training samples (leaves at least 1 per class untouched)."""
    rng = random.Random(random_state)
    candidates = df[~df["hash"].isin(already_selected)]

    picked = []
    remaining_budget = max(0, cap - len(already_selected))
    if remaining_budget <= 0:
        return picked

    for folder, group in candidates.groupby("folder"):
        total_in_class = len(df[df["folder"] == folder])
        target = max(min_per_class, round(total_in_class * pct))
        # Never remove the last training example of a class.
        max_takeable = max(0, total_in_class - 1 - _count_already_in_class(df, already_selected, folder))
        take = min(target, len(group), max_takeable)
        if take <= 0:
            continue
        hashes = group["hash"].tolist()
        rng.shuffle(hashes)
        picked.extend(hashes[:take])

    if len(picked) > remaining_budget:
        rng.shuffle(picked)
        picked = picked[:remaining_budget]

    return picked


def _count_already_in_class(df: pd.DataFrame, already_selected: set, folder: str) -> int:
    if not already_selected:
        return 0
    class_hashes = set(df[df["folder"] == folder]["hash"])
    return len(class_hashes & already_selected)


def build_golden_set(
    dataset_path: str = DATASET_PATH,
    output_path: str = GOLDEN_SET_PATH,
    min_per_class: int = DEFAULT_MIN_PER_CLASS,
    pct: float = DEFAULT_PCT,
    cap: int = DEFAULT_CAP,
    force: bool = False,
) -> dict:
    if os.path.exists(output_path) and not force:
        raise FileExistsError(
            f"{output_path} existe déjà - utilisez --expand pour l'agrandir, "
            f"ou --force pour l'écraser (perd la comparabilité avec les runs passés)."
        )

    df = _load_dataset(dataset_path)
    picked = _select_stratified(df, set(), min_per_class, pct, cap, RANDOM_STATE)
    return _save(output_path, version=1, hashes=picked, df=df)


def expand_golden_set(
    n: int,
    dataset_path: str = DATASET_PATH,
    output_path: str = GOLDEN_SET_PATH,
    min_per_class: int = DEFAULT_MIN_PER_CLASS,
    pct: float = DEFAULT_PCT,
) -> dict:
    existing = load_golden_set(output_path)
    if not existing["hashes"]:
        raise FileNotFoundError(
            f"{output_path} n'existe pas encore - utilisez --create d'abord."
        )

    df = _load_dataset(dataset_path)
    already = set(existing["hashes"])
    # cap = current size + n: expand() bounds how much is ADDED this call,
    # not the lifetime total, so repeated --expand calls keep working.
    picked = _select_stratified(df, already, min_per_class, pct, len(already) + n, RANDOM_STATE + existing["version"])
    new_hashes = existing["hashes"] + picked
    return _save(output_path, version=existing["version"] + 1, hashes=new_hashes, df=df)


def _save(output_path: str, version: int, hashes: list, df: pd.DataFrame) -> dict:
    golden_df = df[df["hash"].isin(hashes)]
    per_label = Counter(golden_df["folder"])

    now = datetime.now(timezone.utc).isoformat()
    payload = {
        "version": version,
        "created_at": now if version == 1 else load_golden_set(output_path).get("created_at", now),
        "updated_at": now,
        "hashes": hashes,
        "per_label_counts": dict(per_label),
        "total": len(hashes),
    }
    with open(output_path, "w") as f:
        json.dump(payload, f, indent=2)
    return payload


def show_golden_set(path: str = GOLDEN_SET_PATH) -> None:
    data = load_golden_set(path)
    if not data.get("hashes"):
        print(f"Aucun golden set trouvé à {path}.")
        return
    print(f"Golden set v{data['version']} - {data['total']} mails (màj {data.get('updated_at', '?')})")
    for label, count in sorted(data.get("per_label_counts", {}).items()):
        print(f"  {label:<35} {count}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--create", action="store_true", help="Première création du golden set")
    group.add_argument("--expand", type=int, metavar="N", help="Ajoute jusqu'à N nouveaux échantillons stratifiés")
    group.add_argument("--show", action="store_true", help="Affiche la composition actuelle")
    parser.add_argument("--force", action="store_true", help="Avec --create: écrase un golden set existant")
    parser.add_argument("--min-per-class", type=int, default=DEFAULT_MIN_PER_CLASS)
    parser.add_argument("--pct", type=float, default=DEFAULT_PCT)
    parser.add_argument("--cap", type=int, default=DEFAULT_CAP, help="Avec --create: taille totale max")
    args = parser.parse_args()

    if args.show:
        show_golden_set()
    elif args.create:
        result = build_golden_set(
            min_per_class=args.min_per_class, pct=args.pct, cap=args.cap, force=args.force
        )
        print(f"✅ Golden set v{result['version']} créé : {result['total']} mails")
        for label, count in sorted(result["per_label_counts"].items()):
            print(f"  {label:<35} {count}")
    elif args.expand:
        result = expand_golden_set(args.expand, min_per_class=args.min_per_class, pct=args.pct)
        print(f"✅ Golden set étendu → v{result['version']}, {result['total']} mails au total")
        for label, count in sorted(result["per_label_counts"].items()):
            print(f"  {label:<35} {count}")
