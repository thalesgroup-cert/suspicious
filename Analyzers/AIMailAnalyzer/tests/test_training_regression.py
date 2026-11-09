"""Evaluation regression (spec, Testing; Ruling E1) and the dataset tool (Ruling E2).

The slow test needs the real dataset as an .npz made by tools/dataset_to_npz.py, kept outside the
repository: AI_EVAL_DATASET=<path> python -m pytest tests -m slow. Optional: AI_EVAL_EMBEDDING
(the array to evaluate, default embeddings_tokens, Ruling E16), AI_EVAL_REPEATS (default 3),
AI_EVAL_REPORT (write the gate report as JSON there; counts and metrics only).
"""
import inspect
import json
import os
import stat
import subprocess
import sys
import time
from dataclasses import asdict
from functools import partial
from pathlib import Path

import numpy as np
import pytest
import torch

import training.recipe as recipe_mod
from training.gate import candidate_recipe, legacy_recipe, run_gate, wilson
from training.groups import campaign_groups, near_duplicate_groups

ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / "tools" / "dataset_to_npz.py"
FOLDERS = (
    "0_LEGIT_INTERNAL_COMMUNICATION", "0_LEGIT_EXTERNAL_COMMUNICATION", "1_SPAM", "1_NEWSLETTER",
    "2_CLASSIC_PHISHING", "2_CLONE_PHISHING", "2_BLACKMAILING_PHISHING", "2_WHALING_PHISHING",
)
DUP_THRESHOLD = 0.95  # the test bed's near_dup_groups
CAMPAIGN_DISTANCE = 0.25  # the production campaign rule, similarity above 0.75 (spec E8)
MIN_ACCURACY = 0.80  # spec: about 0.85, minus seed noise
MAX_DANGEROUS_SAFE = 0.08  # spec: about 5%, plus seed noise


# --- reproducibility (fast) ----------------------------------------------------------------------

def _synthetic(n_per=8, dim=8, seed=0):
    rng = np.random.default_rng(seed)
    centres = rng.normal(size=(len(FOLDERS), dim)) * 4.0
    X = np.vstack([centres[i] + rng.normal(size=(n_per, dim)) for i in range(len(FOLDERS))])
    folders = np.repeat(FOLDERS, n_per)
    dup = np.arange(len(X)) // 2
    return X.astype(np.float32), folders, dup, dup // 2


def test_gate_metrics_are_identical_across_runs_and_global_thread_counts(monkeypatch):
    X, folders, dup, camp = _synthetic()
    recipe = partial(candidate_recipe, epochs=2)
    pinned = inspect.signature(candidate_recipe).parameters["threads"].default
    seen = []
    real_train = recipe_mod._train_head

    def spy(*args, **kwargs):  # the thread count while a head trains
        seen.append(torch.get_num_threads())
        return real_train(*args, **kwargs)

    monkeypatch.setattr(recipe_mod, "_train_head", spy)
    previous = torch.get_num_threads()
    try:
        reports = []
        for threads in (1, 4):  # the recipe pins its own threads, so the global count is moot
            torch.set_num_threads(threads)
            seen.clear()
            reports.append(asdict(run_gate(X, folders, dup, camp, recipe=recipe,
                                           baseline_recipe=recipe, repeats=1)))
            assert seen and set(seen) == {pinned}  # pinned inside every fit
            assert torch.get_num_threads() == threads  # and restored afterwards
    finally:
        torch.set_num_threads(previous)
    assert reports[0] == reports[1]
    assert reports[0]["candidate"]["macro_f1"] > 0


# --- the dataset tool ----------------------------------------------------------------------------

def test_dataset_tool_writes_a_pickle_free_npz_and_prints_counts_only(tmp_path):
    pd = pytest.importorskip("pandas")
    rng = np.random.default_rng(0)
    secret = "SECRET-BODY-TEXT"
    df = pd.DataFrame({
        "hash": [f"h{i}" for i in range(5)],
        "folder": ["1_SPAM", "1_SPAM", "0_LEGIT_EXTERNAL_COMMUNICATION", "2_CLONE_PHISHING",
                   "2_CLONE_PHISHING"],
        "body": [f"{secret} {i}" for i in range(5)],
        "mpnet_vect": [rng.normal(size=768).astype(np.float32) for _ in range(5)],
    })
    src, out = tmp_path / "d.pkl", tmp_path / "d.npz"
    df.to_pickle(src)
    run = subprocess.run([sys.executable, str(TOOL), str(src), str(out)],
                         capture_output=True, text=True, check=True)
    assert secret not in run.stdout + run.stderr
    assert "rows 5" in run.stdout and "1_SPAM 2" in run.stdout
    with np.load(out, allow_pickle=False) as d:
        assert set(d.files) == {"embeddings", "folders", "mail_ids"}
        assert d["embeddings"].dtype == np.float32 and d["embeddings"].shape == (5, 768)
        np.testing.assert_array_equal(d["embeddings"][3], df["mpnet_vect"][3])
        assert d["folders"].dtype.kind == "U" and list(d["folders"]) == list(df["folder"])
        assert list(d["mail_ids"]) == list(df["hash"])
    assert secret.encode() not in out.read_bytes()


WARNING = "never point this at a file you did not produce yourself; unpickling executes code"


def _tool(*args):
    return subprocess.run([sys.executable, str(TOOL), *map(str, args)], capture_output=True,
                          text=True)


def test_dataset_tool_warns_about_unpickling_in_its_docstring_and_help():
    assert WARNING in " ".join(TOOL.read_text().split())
    run = _tool("--help")
    assert run.returncode == 0 and WARNING in " ".join(run.stdout.split())


def test_dataset_tool_refuses_a_world_writable_input(tmp_path):
    src = tmp_path / "d.pkl"
    src.write_bytes(b"not read")
    src.chmod(0o666)
    run = _tool(src, tmp_path / "d.npz")
    assert run.returncode != 0 and "world-writable" in run.stderr
    assert not (tmp_path / "d.npz").exists()


@pytest.mark.skipif(os.geteuid() != 0, reason="chown to another user needs root")
def test_dataset_tool_refuses_an_input_owned_by_another_user(tmp_path):
    src = tmp_path / "d.pkl"
    src.write_bytes(b"not read")
    os.chown(src, 12345, 12345)
    assert not src.stat().st_mode & stat.S_IWOTH
    run = _tool(src, tmp_path / "d.npz")  # we are root, the file is user 12345's
    assert run.returncode != 0 and "not owned" in run.stderr


def test_dataset_tool_is_not_imported_by_the_package_or_the_server():
    for path in [*ROOT.glob("training/*.py"), *ROOT.glob("inference_server/**/*.py")]:
        assert "dataset_to_npz" not in path.read_text(), path


# --- the regression (slow) -----------------------------------------------------------------------

def _stub_baseline(recipe):
    """(candidate, baseline) where the baseline returns the candidate's own logits on the same
    fold, for when imbalanced-learn is missing: the baseline checks then compare it with itself."""
    cache = {}

    def candidate(X, folders, tr, te, *, seed):
        cache[seed, te.tobytes()] = recipe(X, folders, tr, te, seed=seed)
        return cache[seed, te.tobytes()]

    def baseline(X, folders, tr, te, *, seed):
        return cache[seed, te.tobytes()]

    return candidate, baseline


@pytest.mark.slow
@pytest.mark.skipif(not os.environ.get("AI_EVAL_DATASET"), reason="AI_EVAL_DATASET is not set")
def test_recipe_reproduces_the_spec_evidence_on_the_real_dataset():
    key = os.environ.get("AI_EVAL_EMBEDDING", "embeddings_tokens")
    with np.load(os.environ["AI_EVAL_DATASET"], allow_pickle=False) as d:
        X, folders, first128 = d[key], d["folders"], d["embeddings"]
    # Groups on the first-128-token embeddings, as in the test bed and spec E8.
    dup = near_duplicate_groups(first128, DUP_THRESHOLD)
    camp = campaign_groups(first128, CAMPAIGN_DISTANCE, [])
    try:
        import imblearn  # noqa: F401
        recipe, baseline, baseline_name = candidate_recipe, legacy_recipe, "legacy_recipe"
    except ImportError:
        (recipe, baseline), baseline_name = _stub_baseline(candidate_recipe), "stub (candidate)"
    t0 = time.monotonic()
    report = run_gate(X, folders, dup, camp, recipe=recipe, baseline_recipe=baseline,
                      repeats=int(os.environ.get("AI_EVAL_REPEATS", "3")))
    cm = np.array(report.confusion_matrix)
    R = report.pooled_repeats
    accuracy = float(np.trace(cm) / cm.sum())
    summary = {
        "embedding": key, "baseline": baseline_name, "wall_seconds": time.monotonic() - t0,
        "dup_groups": int(len(np.unique(dup))), "campaign_groups": int(len(np.unique(camp))),
        "accuracy": accuracy,
        "dangerous_called_safe_ci": list(wilson(cm[2, 0] / R, cm[2].sum() / R)),
        "report": asdict(report),
    }
    if out := os.environ.get("AI_EVAL_REPORT"):
        Path(out).write_text(json.dumps(summary, indent=1, default=float))
    assert accuracy >= MIN_ACCURACY
    assert report.candidate["dangerous_called_safe"] <= MAX_DANGEROUS_SAFE
