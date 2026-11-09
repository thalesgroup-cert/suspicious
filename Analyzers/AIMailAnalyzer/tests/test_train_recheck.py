"""Plan F, Task 8 (Ruling F11): a gate recheck is a /v2/train job with params.recheck = true. It
runs the gate on the dataset, skips the final fit, writes no bundle and touches no upload URL."""
import os

import numpy as np
import pytest

pytest.importorskip("torch")
pytest.importorskip("fastapi")

from inference_server import training_worker  # noqa: E402
from test_inference_server_train import (  # noqa: E402,F401
    BUNDLE_URLS, FOLDERS, PARAMS, Storage, body, env, make_client, make_dataset, tiny_recipe,
    token_env, train, wait,
)

GATE_KEYS = {"eligible", "checks", "candidate", "baseline", "campaign", "tier_cutoffs"}


def recheck_body(**override):
    b = body(params=dict(PARAMS, recheck=True), **override)
    b.pop("bundle_urls")
    return b


def test_a_recheck_runs_the_gate_and_uploads_nothing(train, env):
    client, _, storage, launches, base = train()
    r = client.post("/v2/train", json=recheck_body(), headers=env)
    assert r.status_code == 202, r.text
    state = wait(client, env)
    assert state["state"] == "succeeded", state
    report = state["report"]
    assert set(report) == GATE_KEYS | {"version_id", "recheck"}  # no rows, ids or mail data
    assert report["version_id"] == PARAMS["version_id"] and report["recheck"] is True
    assert isinstance(report["eligible"], bool) and report["checks"]
    assert [q.method for q in storage.requests] == ["GET"]  # the dataset, no PUT
    assert launches[0][1]["recheck"] is True
    assert not os.listdir(base)


def test_a_recheck_ignores_bundle_urls_it_is_given(train, env):
    client, _, storage, *_ = train()
    b = recheck_body(bundle_urls=dict(BUNDLE_URLS, **{"manifest.json": "http://evil:80/x"}))
    client.post("/v2/train", json=b, headers=env)
    assert wait(client, env)["state"] == "succeeded"
    assert not storage.puts


def test_a_failed_head_floor_is_a_failed_recheck_not_a_failed_job(train, env):
    folders = np.array(list(np.repeat(np.array(FOLDERS[:-1]), 10)) + [FOLDERS[-1]] * 3)
    rng = np.random.default_rng(1)
    data = make_dataset(embeddings=rng.normal(size=(len(folders), 16)).astype(np.float32),
                        folders=folders,
                        campaign_embeddings=rng.normal(size=(len(folders), 64)).astype(np.float32),
                        case_ids=np.arange(len(folders), dtype=np.int64))
    client, *_ = train(storage=Storage(dataset=data))
    client.post("/v2/train", json=recheck_body(), headers=env)
    state = wait(client, env)
    assert state["state"] == "succeeded", state
    assert state["report"]["eligible"] is False
    assert state["report"]["checks"]["head_samples"]["passed"] is False


def test_a_training_job_still_needs_bundle_urls(train, env):
    client, *_ = train()
    b = body()
    b.pop("bundle_urls")
    assert client.post("/v2/train", json=b, headers=env).status_code == 422


def test_the_worker_writes_no_bundle_for_a_recheck(tmp_path, monkeypatch):
    monkeypatch.setitem(training_worker.RECIPES, "candidate", tiny_recipe)
    (tmp_path / training_worker.DATASET).write_bytes(make_dataset())
    fits = []
    monkeypatch.setattr(training_worker, "fit_heads", lambda *a, **k: fits.append(1))
    params = dict(PARAMS, recheck=True, encoder_hash="c" * 64)
    training_worker.run(str(tmp_path), params, 1)
    out = tmp_path / training_worker.OUT
    assert not (out / training_worker.BUNDLE).exists() and not fits
    assert (out / training_worker.PROGRESS).read_text() == "100.0"
