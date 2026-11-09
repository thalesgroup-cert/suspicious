"""The training worker: `python -m inference_server.training_worker <workdir>`, started by
training_job.popen_launcher with subprocess.Popen in its own session (process group).

Inputs: the job's private 0700 directory (argv), the validated params as JSON on stdin (at most
MAX_PARAMS bytes; the recipes are looked up in RECIPES, never named by the caller) and an explicit
minimal environment built by the controller (PATH, HOME and TMPDIR set to the job directory,
LANG, PYTHONDONTWRITEBYTECODE, the BLAS/OpenMP thread variables and AI_TRAIN_* limits; no token,
no storage key, no proxy). It has no network use: the controller downloads the dataset into the
directory and uploads what this process leaves in out/bundle.
Outputs, all under <workdir>/out: `progress` (one number, percent of this process's work),
`result.json` (the manifest pin and the gate summary, or {"error": reason}) and `bundle/`.
An unexpected exception ends the process with a non-zero exit code, which the controller reports
as the code alone; stdout and stderr go to files in the job directory.

Boundary: the worker runs as the same UID as the server, so this is NOT a boundary against code
execution inside the worker (such code could read the server's /proc/<pid>/environ). The controls
are that the worker only parses validated data (params checked by the server, the dataset read by
training.dataset's hardened npz reader with no pickle) and receives no secret by construction."""
import json
import os
import signal
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict
from functools import partial

import numpy as np
import torch

from training.bundle import BundleError, write_bundle
from training.dataset import DatasetError, read_dataset
from training.gate import N_SPLITS, candidate_recipe, legacy_recipe, run_gate
from training.groups import campaign_groups, near_duplicate_groups
from training.recipe import COMPONENTS, Knn, fit_heads, temperature_at_bound

DATASET = "dataset.npz"
OUT = "out"
PROGRESS = "progress"
RESULT = "result.json"
BUNDLE = "bundle"
MAX_PARAMS = 32 * 1024
RECIPE_ID = "candidate-v1"  # training.gate.candidate_recipe
NEAR_DUPLICATE_THRESHOLD = 0.95  # spec E1, the test bed's near_dup_groups
RECIPES = {"candidate": candidate_recipe, "legacy": legacy_recipe}  # baseline ids


class Rejected(Exception):
    """A reason the candidate cannot be built, safe to report (names a head, class or rule)."""


def _exit_with_parent():
    """The worker has its own session, so a server killed by SIGKILL or the OOM killer does not
    take it down: it exits itself once it is reparented."""
    ppid = os.getppid()

    def watch():
        while True:
            time.sleep(2)
            if os.getppid() != ppid:
                os.killpg(os.getpgrp(), signal.SIGKILL)  # this process and anything it started
                os._exit(70)

    threading.Thread(target=watch, daemon=True).start()


def _limit_memory(max_memory_mb):
    """Optional address-space cap (AI_TRAIN_MAX_MEMORY_MB). Off by default: torch reserves virtual
    memory well above what it touches, so a tight value fails early; the container memory limit
    (mem_limit on the ai_inference service, Task 8) is the main control and the controller reports an OOM kill as the exit code."""
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
                           params["campaign_profile"]["distance_threshold"],
                           [tuple(t) for t in data.ties.tolist()])  # CampaignMember links
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
    summary["temperature"] = temperature
    summary["temperature_at_bound"] = {c: temperature_at_bound(t) for c, t in temperature.items()}
    return {"manifest_sha256": sha, "summary": summary}


@contextmanager
def thread_limits(threads):
    """BLAS/OpenMP pools capped for the duration (the environment variables already set the
    defaults; this also covers pools that ignore them)."""
    from threadpoolctl import threadpool_limits  # a scikit-learn dependency
    with threadpool_limits(limits=threads):
        yield


def setup(threads, max_memory_mb):
    """Process-wide limits, applied first in a real worker: torch's inter-op pool must be sized
    before any parallel work starts."""
    torch.set_num_interop_threads(1)
    torch.set_num_threads(threads)
    _limit_memory(max_memory_mb)
    _exit_with_parent()


def read_params(stream) -> dict:
    raw = stream.read(MAX_PARAMS + 1)
    if len(raw) > MAX_PARAMS:
        raise SystemExit("params too large")
    params = json.loads(raw)
    if not isinstance(params, dict):
        raise SystemExit("params must be an object")
    return params


def run(workdir, params, threads):
    """Train and write out/result.json; workdir is the controller's private 0700 directory."""
    out = os.path.join(workdir, OUT)
    os.mkdir(out, 0o700)
    try:
        with thread_limits(threads):
            result = train(workdir, params, threads,
                           lambda pct: _write_atomic(out, PROGRESS, f"{pct:.1f}"))
    except (DatasetError, BundleError, Rejected) as e:
        result = {"error": str(e)}
    _write_atomic(out, RESULT, json.dumps(result, allow_nan=False))


def cli():
    workdir = sys.argv[1]
    threads = int(os.environ.get("AI_TRAIN_THREADS", "2"))
    setup(threads, int(os.environ.get("AI_TRAIN_MAX_MEMORY_MB") or 0))
    run(workdir, read_params(sys.stdin.buffer), threads)


if __name__ == "__main__":
    cli()
