"""The training subprocess (started by training_job.JobController with multiprocessing spawn).

It has no network and no credentials: the controller downloads the dataset into the job's private
directory and uploads what this process leaves in out/bundle. Inputs are the directory and the
validated params (plain values; the recipes are looked up in RECIPES, never named by the caller).
Outputs, all under <workdir>/out: `progress` (one number, percent of this process's work),
`result.json` (the manifest pin and the gate summary, or {"error": reason}) and `bundle/`.
An unexpected exception ends the process with a non-zero exit code, which the controller reports
as the code alone."""
import json
import multiprocessing
import os
import threading
import time
from dataclasses import asdict
from functools import partial

import numpy as np
import torch

from training.bundle import BundleError, write_bundle
from training.dataset import DatasetError, read_dataset
from training.gate import N_SPLITS, candidate_recipe, legacy_recipe, run_gate
from training.groups import campaign_groups, near_duplicate_groups
from training.recipe import COMPONENTS, Knn, fit_heads

DATASET = "dataset.npz"
OUT = "out"
PROGRESS = "progress"
RESULT = "result.json"
BUNDLE = "bundle"
RECIPE_ID = "candidate-v1"  # training.gate.candidate_recipe
NEAR_DUPLICATE_THRESHOLD = 0.95  # spec E1, the test bed's near_dup_groups
RECIPES = {"candidate": candidate_recipe, "legacy": legacy_recipe}  # baseline ids
# Variables the worker has no use for; the parent's environment is inherited through spawn.
SECRET_ENV = ("AI_INFERENCE_TOKEN", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
              "AWS_SESSION_TOKEN")


class Rejected(Exception):
    """A reason the candidate cannot be built, safe to report (names a head, class or rule)."""


def _scrub_env():
    for k in SECRET_ENV:
        os.environ.pop(k, None)


def _exit_with_parent():
    """A spawned worker whose server died (SIGKILL, OOM) would otherwise train on as an orphan."""
    ppid = os.getppid()

    def watch():
        while True:
            time.sleep(2)
            if os.getppid() != ppid:
                os._exit(70)

    threading.Thread(target=watch, daemon=True).start()


def _limit_memory(max_memory_mb):
    """Optional address-space cap (AI_TRAIN_MAX_MEMORY_MB). Off by default: torch reserves virtual
    memory well above what it touches, so a tight value fails early; the container limit is the
    main control and the controller reports an OOM kill as the exit code."""
    if max_memory_mb:
        import resource
        b = int(max_memory_mb) * 2**20
        resource.setrlimit(resource.RLIMIT_AS, (b, b))


def _write_atomic(out, name, text):
    tmp = os.path.join(out, f".{name}.tmp")
    with open(tmp, "w") as fh:
        fh.write(text)
    os.replace(tmp, os.path.join(out, name))


def _plain(obj):
    """JSON-ready copy of the gate report (numpy scalars and arrays to Python values)."""
    def conv(v):
        if isinstance(v, np.generic):
            return v.item()
        if isinstance(v, np.ndarray):
            return v.tolist()
        raise TypeError(type(v).__name__)
    return json.loads(json.dumps(obj, default=conv))


def train(workdir, params, threads, report_progress):
    data = read_dataset(os.path.join(workdir, DATASET))
    X, folders = data.embeddings, data.folders
    dup = near_duplicate_groups(data.campaign_embeddings, NEAR_DUPLICATE_THRESHOLD)
    camp = campaign_groups(data.campaign_embeddings,
                           params["campaign_profile"]["distance_threshold"], [])
    repeats, seed, epochs = params["repeats"], params["seed"], params["epochs"]
    total = repeats * N_SPLITS * 2 * 2 + 2  # gate fits (2 groupings x 2 recipes) + the final fit
    done = [0]

    def counted(fn):
        def run(*a, **k):
            out = fn(*a, **k)
            done[0] += 1
            report_progress(100 * done[0] / total)
            return out
        return run

    recipe = counted(partial(RECIPES["candidate"], epochs=epochs, threads=threads))
    baseline = counted(partial(RECIPES[params["baseline"]], epochs=epochs, threads=threads))
    report = run_gate(X, folders, dup, camp, baseline_recipe=baseline, recipe=recipe,
                      repeats=repeats, seed0=seed)
    if not report.checks["head_samples"]["passed"]:
        raise Rejected("gate: " + report.checks["head_samples"]["detail"])
    gate = _plain(asdict(report))
    gate["eligible"] = report.eligible

    heads = fit_heads(X, folders, seed=seed, epochs=epochs, threads=threads)
    # the gate fitted one temperature per component on each held-out half; the median is stored
    temperature = {c: float(np.median([t[c] for t in report.temperatures])) for c in COMPONENTS}
    calibration = {
        "temperature": temperature,
        "tier_cutoffs": gate["tier_cutoffs"],
        "held_out_groups": {"near_duplicate": int(len(np.unique(dup))),
                            "campaign": gate["campaign"]["groups"], "seeds": gate["seeds"]},
    }
    manifest = {
        "version_id": params["version_id"], "recipe_id": RECIPE_ID,
        "preprocessing_version": params["preprocessing_version"],
        "encoder_id": params["encoder_id"], "encoder_hash": params["encoder_hash"],
        "ledger_digest": params["ledger_digest"],
        "campaign_refs_digest": params["campaign_refs_digest"],
        "metrics": gate["candidate"], "gate": gate, "parent_version": params["parent_version"],
        "trainer_revision": params["trainer_revision"], "baseline_recipe": params["baseline"],
        "seed": seed, "repeats": repeats, "epochs": epochs, "rows": int(len(X)),
    }
    sha = write_bundle(os.path.join(workdir, OUT, BUNDLE), heads=heads, calibration=calibration,
                       knn=Knn.build(X, folders, data.case_ids),
                       campaign_profile=params["campaign_profile"], manifest=manifest)
    report_progress(100.0)
    summary = {k: gate[k] for k in ("eligible", "checks", "candidate", "baseline", "campaign",
                                    "tier_cutoffs")}
    return {"manifest_sha256": sha, "summary": summary}


def main(workdir, params, threads, max_memory_mb=0):
    """Entry point; workdir is the controller's private 0700 directory."""
    if multiprocessing.parent_process() is not None:  # a real child, not an in-process test
        _scrub_env()
        _exit_with_parent()
        _limit_memory(max_memory_mb)
    torch.set_num_threads(threads)
    out = os.path.join(workdir, OUT)
    os.mkdir(out, 0o700)
    try:
        result = train(workdir, params, threads,
                       lambda pct: _write_atomic(out, PROGRESS, f"{pct:.1f}"))
    except (DatasetError, BundleError, Rejected) as e:
        result = {"error": str(e)}
    _write_atomic(out, RESULT, json.dumps(result, allow_nan=False))
