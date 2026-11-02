"""
Tests for the single-job training API (/v2/train): inference_server/training_job.py (controller,
URL rules, uploads), inference_server/training_worker.py (the subprocess) and
training/dataset.py (the downloaded dataset reader).

Most tests start the worker in-process through an injected launcher (a thread) with a tiny
recipe; storage is an httpx.MockTransport. Two tests use the real spawn launcher.
"""
import hashlib
import http.server
import io
import json
import logging
import math
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import numpy as np
import pytest

torch = pytest.importorskip("torch")
pytest.importorskip("sentence_transformers")
pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")

from inference_server import server, training_job, training_worker  # noqa: E402
from test_inference_server_v2 import TOKEN, make_client, token_env  # noqa: E402,F401
from training import dataset as dataset_mod  # noqa: E402
from training.bundle import BUNDLE_FILES, read_bundle  # noqa: E402

FOLDERS = dataset_mod.FOLDERS
HOST = "rustfs:9000"
SECRET = "X-Amz-Signature=deadbeefsecret"
DATASET_URL = f"http://{HOST}/models/job-1/dataset.npz?{SECRET}"
NAMES = (*BUNDLE_FILES, "manifest.json")
BUNDLE_URLS = {n: f"http://{HOST}/models/job-1/bundle/{n}?{SECRET}" for n in NAMES}
PROFILE = {"embedding_version": "cmp-e1", "metric": "cosine", "distance_threshold": 0.25,
           "min_members": 3, "n_neighbours": 20, "window_days": 15}
PARAMS = {
    "version_id": "v-test-1", "seed": 0, "repeats": 1, "epochs": 1, "baseline": "candidate",
    "preprocessing_version": "chunkmean-tokens-v1", "parent_version": "v0",
    "ledger_digest": "a" * 64, "campaign_refs_digest": "b" * 64,
    "encoder_id": "paraphrase-multilingual-mpnet-base-v2", "encoder_hash": "c" * 64,
    "trainer_revision": "9f8d6912", "campaign_profile": PROFILE,
}
TERMINAL = {"succeeded", "failed", "cancelled"}
ROOT = Path(__file__).resolve().parent.parent


def make_dataset(n_per=10, dim=16, **override) -> bytes:
    rng = np.random.default_rng(0)
    centres = rng.normal(size=(len(FOLDERS), dim)) * 4
    X = np.vstack([centres[i] + rng.normal(size=(n_per, dim)) for i in range(len(FOLDERS))])
    arrays = {
        "embeddings": X.astype(np.float32),
        "campaign_embeddings": rng.normal(size=(len(X), 64)).astype(np.float32),
        "folders": np.repeat(np.array(FOLDERS), n_per),
        "case_ids": np.arange(1, len(X) + 1, dtype=np.int64),
    }
    arrays.update(override)
    arrays = {k: v for k, v in arrays.items() if v is not None}
    buf = io.BytesIO()
    np.savez(buf, **arrays)
    return buf.getvalue()


def tiny_recipe(X, folders, train_idx, test_idx, *, seed, epochs=1, threads=2):
    """Fast stand-in for the recipes: noisy one-hot logits of the true main class."""
    y = np.array([int(f[0]) for f in folders[test_idx]])
    z = np.full((len(test_idx), 3), -1.0)
    z[np.arange(len(y)), y] = 1.0
    noise = np.random.default_rng(seed).normal(scale=0.3, size=z.shape)
    return {"hierarchy": z + noise, "knn": z - noise}


RELEASE = threading.Event()  # set: blocking_recipe returns; set by ThreadHandle.terminate too
ENTERED = threading.Event()


def blocking_recipe(*args, **kwargs):
    ENTERED.set()
    if not RELEASE.wait(30):
        raise RuntimeError("test recipe never released")
    if getattr(blocking_recipe, "abort", False):
        raise SystemExit(-15)
    return tiny_recipe(*args, **kwargs)


class ThreadHandle:
    """In-process stand-in for a multiprocessing.Process, same interface."""

    def __init__(self, target, args):
        self.exitcode = None
        self.terminated = 0

        def run():
            try:
                target(*args)
                code = 0
            except SystemExit as e:
                code = e.code if isinstance(e.code, int) else 1
            except BaseException:  # noqa: BLE001
                code = 1
            self.exitcode = code

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()

    def is_alive(self):
        return self.thread.is_alive()

    def join(self, timeout=None):
        self.thread.join(timeout)

    def terminate(self):
        self.terminated += 1
        blocking_recipe.abort = True
        RELEASE.set()

    kill = terminate


class Storage:
    """MockTransport handler: serves the dataset, records PUTs."""

    def __init__(self, dataset=None, response=None):
        self.dataset = make_dataset() if dataset is None else dataset
        self.response = response  # callable(request) -> httpx.Response, overrides GET
        self.puts = {}
        self.requests = []

    def __call__(self, request):
        self.requests.append(request)
        if request.method == "PUT":
            self.puts[str(request.url)] = request.read()
            return httpx.Response(200)
        if self.response:
            return self.response(request)
        return httpx.Response(200, headers={"Content-Length": str(len(self.dataset))},
                              stream=httpx.ByteStream(self.dataset))


@pytest.fixture(autouse=True)
def _reset_events():
    RELEASE.clear()
    ENTERED.clear()
    blocking_recipe.abort = False
    yield
    RELEASE.set()


@pytest.fixture
def env(monkeypatch, token_env):  # noqa: F811
    monkeypatch.setenv("AI_BUNDLE_HOSTS", f"other:80, {HOST.upper()} ,")
    monkeypatch.delenv("AI_TRAIN_MAX_SECONDS", raising=False)
    monkeypatch.delenv("AI_TRAIN_THREADS", raising=False)
    return token_env


@pytest.fixture
def train(make_client, tmp_path, monkeypatch, env):  # noqa: F811
    """Factory: (client, controller, storage, launches) with an in-process launcher."""

    def make(storage=None, launcher=None, recipe=tiny_recipe):
        storage = storage or Storage()
        launches = []

        def thread_launcher(workdir, params, threads, max_memory_mb):
            launches.append((workdir, params, threads, max_memory_mb))
            return ThreadHandle(training_worker.run, (workdir, params, threads))

        monkeypatch.setitem(training_worker.RECIPES, "candidate", recipe)
        monkeypatch.setitem(training_worker.RECIPES, "legacy", recipe)
        base = tmp_path / "train-tmp"
        base.mkdir(exist_ok=True)
        controller = training_job.JobController(
            launcher=launcher or thread_launcher, transport=httpx.MockTransport(storage),
            tmp_base=str(base), grace_seconds=0.5, poll_seconds=0.02)
        client = make_client()
        monkeypatch.setattr(server.trainer, "__dict__", controller.__dict__)
        return client, controller, storage, launches, base

    return make


def body(**override):
    b = {"job_id": "job-1", "dataset_url": DATASET_URL, "bundle_urls": dict(BUNDLE_URLS),
         "params": dict(PARAMS)}
    b.update(override)
    return b


def wait(client, headers, job_id="job-1", states=TERMINAL, timeout=60):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        r = client.get(f"/v2/train/{job_id}", headers=headers)
        assert r.status_code == 200, r.text
        if r.json()["state"] in states:
            return r.json()
        time.sleep(0.02)
    raise AssertionError(f"job never reached {states}: {r.json()}")


def assert_clean_error(error):
    assert error
    for leak in (HOST, "rustfs", "evil", "Signature", "deadbeef", "?", "http"):
        assert leak not in error, error


# --- auth and request validation -------------------------------------------------------------


def test_train_routes_require_the_token(train, env):
    client, *_ = train()
    assert client.post("/v2/train", json=body()).status_code == 401
    assert client.get("/v2/train/job-1").status_code == 401
    assert client.post("/v2/train/job-1/cancel").status_code == 401
    bad = {"Authorization": "Bearer nope"}
    assert client.post("/v2/train", json=body(), headers=bad).status_code == 401


@pytest.mark.parametrize("job_id", ["", "a" * 65, "../x", "a b", "job/1", "jöb", "a\n"])
def test_bad_job_id_is_refused(train, env, job_id):
    client, _, storage, launches, _ = train()
    r = client.post("/v2/train", json=body(job_id=job_id), headers=env)
    assert r.status_code == 422
    assert not launches and not storage.requests


def test_unknown_or_malformed_job_id_is_404(train, env):
    client, *_ = train()
    assert client.get("/v2/train/nope", headers=env).status_code == 404
    assert client.get("/v2/train/a%20b", headers=env).status_code == 404
    assert client.post("/v2/train/nope/cancel", headers=env).status_code == 404


@pytest.mark.parametrize("urls", [
    {**BUNDLE_URLS, "../evil.json": BUNDLE_URLS["manifest.json"]},
    {**BUNDLE_URLS, "model.pth": BUNDLE_URLS["manifest.json"]},
    {k: v for k, v in BUNDLE_URLS.items() if k != "manifest.json"},
])
def test_bundle_url_names_must_be_the_fixed_set(train, env, urls):
    client, _, storage, launches, _ = train()
    r = client.post("/v2/train", json=body(bundle_urls=urls), headers=env)
    assert r.status_code == 422
    assert not launches and not storage.requests
    assert SECRET not in r.text


@pytest.mark.parametrize("params", [
    {**PARAMS, "baseline": "os.system"},
    {**PARAMS, "recipe": "evil.module:run"},
    {**PARAMS, "epochs": 0},
    {**PARAMS, "repeats": 100},
    {**PARAMS, "preprocessing_version": "legacy-first128"},
    {**PARAMS, "version_id": "../v"},
    {**PARAMS, "campaign_profile": {**PROFILE, "distance_threshold": 2}},
    {k: v for k, v in PARAMS.items() if k != "seed"},
])
def test_params_are_strict(train, env, params):
    client, _, _, launches, _ = train()
    assert client.post("/v2/train", json=body(params=params), headers=env).status_code == 422
    assert not launches


def test_request_body_is_capped(train, env):
    client, _, _, launches, _ = train()
    big = body(params={**PARAMS, "campaign_profile": {**PROFILE, "pad": "x" * 70_000}})
    assert client.post("/v2/train", json=big, headers=env).status_code == 413
    assert not launches


def test_validation_errors_do_not_echo_urls(train, env):
    client, *_ = train()
    r = client.post("/v2/train", json=body(dataset_url=123), headers=env)
    assert r.status_code == 422
    r = client.post("/v2/train", json=body(params={**PARAMS, "seed": DATASET_URL}), headers=env)
    assert r.status_code == 422 and SECRET not in r.text


# --- URL rules -------------------------------------------------------------------------------


@pytest.mark.parametrize("url", [
    f"http://evil:9000/d?{SECRET}",
    f"http://{HOST}.evil.example/d?{SECRET}",
    f"http://rustfs:9001/d?{SECRET}",
    f"http://rustfs/d?{SECRET}",
    f"ftp://{HOST}/d?{SECRET}",
    f"file:///etc/passwd?{SECRET}",
    f"gopher://{HOST}/d?{SECRET}",
    f"http://user:pw@{HOST}/d?{SECRET}",
    f"http://user@{HOST}/d?{SECRET}",
    f"http://evil@{HOST}/d?{SECRET}",
    f"http://{HOST}\\@evil/d?{SECRET}",
    f"http://{HOST}#@evil/d?{SECRET}",
    f"http://{HOST}/d d?{SECRET}",
    f"http://%72ustfs:9000/d?{SECRET}",
    f"http://rustfs:9000\n/d?{SECRET}",
    f"//{HOST}/d?{SECRET}",
    f"http://[::1]:9000/d?{SECRET}",
    f"http://127.0.0.1:9000/d?{SECRET}",
])
def test_dataset_url_rules(train, env, url):
    client, _, storage, launches, base = train()
    r = client.post("/v2/train", json=body(dataset_url=url), headers=env)
    assert r.status_code == 202
    state = wait(client, env)
    assert state["state"] == "failed"
    assert_clean_error(state["error"])
    assert not launches and not storage.requests
    assert not os.listdir(base)


def test_bundle_url_host_is_checked_before_anything_runs(train, env):
    client, _, storage, launches, _ = train()
    urls = {**BUNDLE_URLS, "calibration.json": f"http://evil:9000/c?{SECRET}"}
    client.post("/v2/train", json=body(bundle_urls=urls), headers=env)
    state = wait(client, env)
    assert state["state"] == "failed" and "calibration.json" in state["error"]
    assert_clean_error(state["error"])
    assert not launches and not storage.requests


def test_empty_allow_list_refuses_everything(train, env, monkeypatch):
    monkeypatch.delenv("AI_BUNDLE_HOSTS")
    client, _, storage, launches, _ = train()
    client.post("/v2/train", json=body(), headers=env)
    assert wait(client, env)["state"] == "failed"
    assert not launches and not storage.requests


def test_punycode_hosts_fail_closed():
    host = "xn--bcher-kva.example:9000"
    with pytest.raises(training_job.JobError):
        training_job.check_url(f"http://{host}/a", {host}, "x")


def test_allow_list_is_host_and_port(monkeypatch):
    monkeypatch.setenv("AI_BUNDLE_HOSTS", "RustFS:9000, [::1]:8080, bad, http://x:1/, u@h:1")
    assert training_job.allowed_hosts() == {"rustfs:9000", "::1:8080"}
    assert training_job.check_url("https://rustfs:9000/a?b=c", {"rustfs:9000"}, "x")
    assert training_job.check_url("http://[::1]:8080/a", {"::1:8080"}, "x")
    with pytest.raises(training_job.JobError):
        training_job.check_url("https://rustfs/a", {"rustfs:9000"}, "x")  # 443


def _ok_head(**headers):
    def respond(request):
        return httpx.Response(200, headers=headers, stream=httpx.ByteStream(b"x" * 10))
    return respond


@pytest.mark.parametrize("respond, why", [
    (lambda r: httpx.Response(302, headers={"Location": "http://evil/"}), "redirect"),
    (lambda r: httpx.Response(307, headers={"Location": DATASET_URL}), "redirect"),
    (lambda r: httpx.Response(404), "HTTP 404"),
    (_ok_head(), "content length"),
    (_ok_head(**{"Content-Length": str(200 * 2**20 + 1)}), "cap"),
    (_ok_head(**{"Content-Length": "abc"}), "content length"),
    (_ok_head(**{"Content-Length": "10, 10"}), "content length"),
    (_ok_head(**{"Content-Length": "+10"}), "content length"),
    (_ok_head(**{"Content-Length": "0x10"}), "content length"),
    (_ok_head(**{"Content-Length": "20"}), "shorter"),
    (_ok_head(**{"Content-Length": "5"}), "longer"),
    (_ok_head(**{"Content-Length": "10", "Content-Encoding": "gzip"}), "encoding"),
])
def test_download_responses_are_refused(train, env, respond, why):
    storage = Storage(response=respond)
    client, _, _, launches, base = train(storage=storage)
    client.post("/v2/train", json=body(), headers=env)
    state = wait(client, env)
    assert state["state"] == "failed" and why in state["error"]
    assert_clean_error(state["error"])
    assert not launches and not storage.puts
    assert not os.listdir(base)
    assert len([r for r in storage.requests if r.method == "GET"]) == 1  # no redirect followed


def test_streaming_cap_holds_even_with_a_matching_content_length(train, env, monkeypatch):
    monkeypatch.setattr(training_job, "MAX_DOWNLOAD", 1000)
    data = b"x" * 5000
    storage = Storage(response=lambda r: httpx.Response(
        200, headers={"Content-Length": "5000"}, stream=httpx.ByteStream(data)))
    client, *_ = train(storage=storage)
    client.post("/v2/train", json=body(), headers=env)
    assert "cap" in wait(client, env)["error"]


def test_transport_errors_do_not_leak_the_url(train, env):
    def boom(request):
        raise httpx.ConnectError(f"cannot connect to {request.url}")
    client, *_ = train(storage=Storage(response=boom))
    client.post("/v2/train", json=body(), headers=env)
    state = wait(client, env)
    assert state["state"] == "failed" and "ConnectError" in state["error"]
    assert_clean_error(state["error"])


def test_client_ignores_proxy_environment(train, env, monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://evil:3128")
    monkeypatch.setenv("ALL_PROXY", "http://evil:3128")
    _, controller, *_ = train()
    with controller._client() as c:
        assert c._trust_env is False
        assert c.follow_redirects is False


# --- the job ---------------------------------------------------------------------------------


def test_successful_job_trains_writes_and_uploads_the_bundle(train, env, tmp_path):
    client, _, storage, launches, base = train()
    r = client.post("/v2/train", json=body(), headers=env)
    assert r.status_code == 202 and r.json()["state"] in ("queued", "running")
    state = wait(client, env)
    assert state["state"] == "succeeded", state
    assert state["progress"] == 100.0 and state["error"] is None
    report = state["report"]
    assert report["uploaded"] == list(NAMES)
    assert set(report["checks"]) and isinstance(report["eligible"], bool)
    assert {"candidate", "baseline", "tier_cutoffs", "campaign"} <= set(report)

    get = [q for q in storage.requests if q.method == "GET"]
    assert len(get) == 1 and str(get[0].url) == DATASET_URL
    assert get[0].headers["accept-encoding"] == "identity"
    assert set(storage.puts) == set(BUNDLE_URLS.values())
    put_order = [str(q.url) for q in storage.requests if q.method == "PUT"]
    assert put_order[-1] == BUNDLE_URLS["manifest.json"]

    # the uploaded bytes are a valid bundle under the reported pin
    out = tmp_path / "uploaded"
    (out / "heads").mkdir(parents=True)
    for name, url in BUNDLE_URLS.items():
        (out / name).write_bytes(storage.puts[url])
    pin = report["manifest_sha256"]
    assert pin == hashlib.sha256(storage.puts[BUNDLE_URLS["manifest.json"]]).hexdigest()
    bundle = read_bundle(out, manifest_sha256=pin)
    m = bundle.manifest
    assert m["version_id"] == "v-test-1" and m["parent_version"] == "v0"
    assert m["ledger_digest"] == "a" * 64 and m["encoder_hash"] == "c" * 64
    assert m["preprocessing_version"] == "chunkmean-tokens-v1" and m["input_dim"] == 16
    assert m["gate"]["eligible"] == report["eligible"] and m["baseline_recipe"] == "candidate"
    assert bundle.campaign_profile == PROFILE
    assert bundle.knn.case_ids.tolist() == list(range(1, 81))
    assert set(bundle.calibration["temperature"]) == {"hierarchy", "knn"}

    # the worker never sees a URL; nothing stays on disk
    assert launches and "http" not in repr(launches) and SECRET not in repr(launches)
    assert not os.listdir(base)


def test_job_dir_is_private(train, env, monkeypatch):
    seen = {}

    def launcher(workdir, params, threads, max_memory_mb):
        seen["mode"] = os.stat(workdir).st_mode & 0o777
        seen["dataset"] = os.stat(os.path.join(workdir, "dataset.npz")).st_mode & 0o777
        return ThreadHandle(training_worker.run, (workdir, params, threads))

    client, *_ = train(launcher=launcher)
    client.post("/v2/train", json=body(), headers=env)
    assert wait(client, env)["state"] == "succeeded"
    assert seen == {"mode": 0o700, "dataset": 0o600}


def test_running_job_shows_progress_and_blocks_a_second_one(train, env):
    client, _, storage, launches, _ = train(recipe=blocking_recipe)
    assert client.post("/v2/train", json=body(), headers=env).status_code == 202
    assert ENTERED.wait(30)
    state = wait(client, env, states={"running"})
    assert isinstance(state["progress"], float) and 0 <= state["progress"] <= 100

    r = client.post("/v2/train", json=body(job_id="job-2"), headers=env)
    assert r.status_code == 409
    again = client.post("/v2/train", json=body(), headers=env)  # same id: its state, no new job
    assert again.status_code == 200 and again.json()["state"] == "running"
    assert len(launches) == 1
    assert client.get("/v2/train/job-2", headers=env).status_code == 404

    # classify keeps answering while the job runs
    c = client.post("/v2/models/ai_mail/classify", json={"mail_body": "hello"}, headers=env)
    assert c.status_code == 200

    RELEASE.set()
    assert wait(client, env)["state"] == "succeeded"


def test_same_job_id_after_finish_returns_the_stored_state(train, env):
    client, _, storage, launches, _ = train()
    client.post("/v2/train", json=body(), headers=env)
    done = wait(client, env)
    n_requests = len(storage.requests)
    r = client.post("/v2/train", json=body(), headers=env)
    assert r.status_code == 200 and r.json() == done
    assert len(launches) == 1 and len(storage.requests) == n_requests
    # a new id may start once the first finished
    assert client.post("/v2/train", json=body(job_id="job-2"), headers=env).status_code == 202
    assert wait(client, env, "job-2")["state"] == "succeeded"


def test_cancel_stops_the_worker_and_leaves_nothing(train, env):
    client, controller, storage, launches, base = train(recipe=blocking_recipe)
    client.post("/v2/train", json=body(), headers=env)
    assert ENTERED.wait(30)
    r = client.post("/v2/train/job-1/cancel", headers=env)
    assert r.status_code == 202
    state = wait(client, env)
    assert state["state"] == "cancelled" and state["report"] is None
    assert not storage.puts
    assert not os.listdir(base)
    # cancelling a finished job changes nothing
    assert client.post("/v2/train/job-1/cancel", headers=env).json()["state"] == "cancelled"


def test_cancel_while_queued_never_launches(train, env, monkeypatch):
    gate = threading.Event()
    real = training_job.JobController._download

    def slow(self, *a, **k):
        gate.wait(10)
        return real(self, *a, **k)

    monkeypatch.setattr(training_job.JobController, "_download", slow)
    client, _, storage, launches, base = train()
    client.post("/v2/train", json=body(), headers=env)
    client.post("/v2/train/job-1/cancel", headers=env)
    gate.set()
    assert wait(client, env)["state"] == "cancelled"
    assert not launches and not storage.puts and not os.listdir(base)


def test_wall_time_limit_kills_the_worker(train, env, monkeypatch):
    monkeypatch.setenv("AI_TRAIN_MAX_SECONDS", "1")
    handles = []

    def launcher(workdir, params, threads, max_memory_mb):
        handles.append(ThreadHandle(training_worker.run, (workdir, params, threads)))
        return handles[-1]

    client, _, storage, _, base = train(launcher=launcher, recipe=blocking_recipe)
    client.post("/v2/train", json=body(), headers=env)
    state = wait(client, env)
    assert state["state"] == "failed" and state["error"] == "wall-time limit reached"
    assert handles[0].terminated and not storage.puts and not os.listdir(base)


class DeadHandle:
    def __init__(self, code):
        self.exitcode = code

    def is_alive(self):
        return False

    def join(self, timeout=None):
        pass

    def terminate(self):
        pass

    kill = terminate


@pytest.mark.parametrize("code", [1, -9, 137])
def test_worker_crash_reports_only_the_exit_code(train, env, code):
    client, _, storage, _, base = train(launcher=lambda *a: DeadHandle(code))
    client.post("/v2/train", json=body(), headers=env)
    state = wait(client, env)
    assert state == {"job_id": "job-1", "state": "failed", "progress": state["progress"],
                     "report": None, "error": f"worker exited with code {code}"}
    assert not storage.puts and not os.listdir(base)


def test_a_bad_dataset_fails_with_a_named_reason(train, env):
    storage = Storage(dataset=make_dataset(folders=np.repeat(np.array(["9_EVIL"] * 8), 10)))
    client, *_ = train(storage=storage)
    client.post("/v2/train", json=body(), headers=env)
    state = wait(client, env)
    assert state["state"] == "failed" and "folders" in state["error"]
    assert not storage.puts


def test_head_floor_fails_the_job_naming_head_and_class(train, env):
    folders = np.array(list(np.repeat(np.array(FOLDERS[:-1]), 10)) + [FOLDERS[-1]] * 3)
    X = np.random.default_rng(1).normal(size=(len(folders), 16)).astype(np.float32)
    data = make_dataset(embeddings=X, folders=folders,
                        campaign_embeddings=np.random.default_rng(2).normal(
                            size=(len(folders), 64)).astype(np.float32),
                        case_ids=np.arange(len(folders), dtype=np.int64))
    client, _, storage, *_ = train(storage=Storage(dataset=data))
    client.post("/v2/train", json=body(), headers=env)
    state = wait(client, env)
    assert state["state"] == "failed" and "dangerous" in state["error"]
    assert not storage.puts


def test_failed_upload_fails_the_job(train, env):
    storage = Storage()
    real = storage.__call__

    def handler(request):
        if request.method == "PUT":
            storage.requests.append(request)
            return httpx.Response(403)
        return real(request)

    client, controller, *_ = train(storage=storage)
    controller.transport = httpx.MockTransport(handler)
    client.post("/v2/train", json=body(), headers=env)
    state = wait(client, env)
    assert state["state"] == "failed" and "HTTP 403" in state["error"]
    assert_clean_error(state["error"])


def test_threads_are_passed_to_the_worker(train, env, monkeypatch):
    monkeypatch.setenv("AI_TRAIN_THREADS", "3")
    got = {}

    def recipe(*a, threads, **k):
        got["threads"] = threads
        return tiny_recipe(*a, threads=threads, **k)

    client, _, _, launches, _ = train(recipe=recipe)
    client.post("/v2/train", json=body(), headers=env)
    assert wait(client, env)["state"] == "succeeded"
    assert launches[0][2] == 3 and got["threads"] == 3


def test_first_job_sweeps_leftover_job_dirs_not_the_import(train, env, monkeypatch):
    client, controller, storage, launches, base = train()
    (base / "ai-train-old").mkdir()
    (base / "ai-train-old" / "dataset.npz").write_bytes(b"x")
    (base / "keep").mkdir()
    assert sorted(os.listdir(base)) == ["ai-train-old", "keep"]  # constructing swept nothing
    client.post("/v2/train", json=body(), headers=env)
    assert wait(client, env)["state"] == "succeeded"
    assert sorted(os.listdir(base)) == ["keep"]


def test_tmp_base_comes_from_the_environment_at_first_use(tmp_path, monkeypatch):
    c = training_job.JobController()
    monkeypatch.setenv("AI_TRAIN_TMPDIR", str(tmp_path))
    assert c.base_dir() == str(tmp_path)


def test_importing_the_server_does_not_touch_the_temp_dir(tmp_path):
    (tmp_path / "ai-train-old").mkdir()
    env = {k: v for k, v in os.environ.items() if k in ("PATH", "PYTHONPATH", "HOME")}
    subprocess.run([sys.executable, "-c", "import inference_server.server"], cwd=ROOT, check=True,
                   env={**env, "AI_TRAIN_TMPDIR": str(tmp_path)}, capture_output=True, timeout=120)
    assert os.listdir(tmp_path) == ["ai-train-old"]


def test_finished_jobs_are_bounded(tmp_path):
    c = training_job.JobController(tmp_base=str(tmp_path))
    for i in range(training_job.MAX_JOBS_KEPT + 5):
        c.jobs[f"j{i}"] = training_job.Job(f"j{i}", state="failed")
        c._evict()
    assert len(c.jobs) == training_job.MAX_JOBS_KEPT and "j0" not in c.jobs


# --- progress channel ------------------------------------------------------------------------


@pytest.mark.parametrize("content, expected", [
    (b"42.5", 42.5), (b"nan", None), (b"inf", None), (b"1e9", 100.0), (b"-5", 0.0),
    (b"x" * 100_000, None), (b"", None), (b"12\n{\"state\":\"succeeded\"}", None),
])
def test_progress_file_is_a_bounded_number(tmp_path, content, expected):
    out = tmp_path / "out"
    out.mkdir()
    (out / "progress").write_bytes(content)
    assert training_job._read_progress(str(tmp_path)) == expected


def test_progress_symlink_is_ignored(tmp_path):
    (tmp_path / "out").mkdir()
    (tmp_path / "secret").write_bytes(b"50")
    os.symlink(tmp_path / "secret", tmp_path / "out" / "progress")
    assert training_job._read_progress(str(tmp_path)) is None


# --- real subprocess -------------------------------------------------------------------------


def test_real_worker_trains_a_bundle(make_client, tmp_path, monkeypatch, env):  # noqa: F811
    storage = Storage()
    base = tmp_path / "b"
    base.mkdir()
    controller = training_job.JobController(transport=httpx.MockTransport(storage),
                                            tmp_base=str(base), poll_seconds=0.1)
    client = make_client()
    monkeypatch.setattr(server.trainer, "__dict__", controller.__dict__)
    client.post("/v2/train", json=body(), headers=env)
    state = wait(client, env, timeout=300)
    assert state["state"] == "succeeded", state
    assert len(storage.puts) == len(NAMES) and not os.listdir(base)


def test_real_worker_killed_becomes_failed(make_client, tmp_path, monkeypatch, env):  # noqa: F811
    def killing_launcher(*args):
        p = training_job.popen_launcher(*args)
        p.kill()  # what the OOM killer does
        return p

    storage = Storage()
    base = tmp_path / "b"
    base.mkdir()
    controller = training_job.JobController(launcher=killing_launcher,
                                            transport=httpx.MockTransport(storage),
                                            tmp_base=str(base), poll_seconds=0.05)
    client = make_client()
    monkeypatch.setattr(server.trainer, "__dict__", controller.__dict__)
    client.post("/v2/train", json=body(), headers=env)
    state = wait(client, env, timeout=60)
    assert state["state"] == "failed" and state["error"] == "worker exited with code -9"
    assert not storage.puts and not os.listdir(base)


# --- the worker process: environment, threads, process group, orphan ---------------------------


SECRETS = {"AI_INFERENCE_TOKEN": "TOPSECRET-TOKEN", "AWS_SECRET_ACCESS_KEY": "AWSSECRET",
           "AWS_ACCESS_KEY_ID": "AKIAEXAMPLE", "MINIO_SECRET_KEY": "MINIOSECRET",
           "MYSQL_PASSWORD": "DBPASSWORD", "VAULT_SECRET": "VAULTSECRET",
           "HTTP_PROXY": "http://proxy:3128", "HTTPS_PROXY": "http://proxy:3128",
           "http_proxy": "http://proxy:3128", "PYTHONPATH": "/evil", "LD_PRELOAD": "/evil.so"}


def _probe(tmp_path, monkeypatch, threads=3):
    """Start tests/train_probe_worker.py through the real launcher; return (handle, report)."""
    for k, v in SECRETS.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(training_job, "WORKER_MODULE", "tests.train_probe_worker")
    workdir = tmp_path / "w"
    workdir.mkdir(mode=0o700)
    handle = training_job.popen_launcher(str(workdir), {"mode": "probe"}, threads, 0)
    report = workdir / "probe.json"
    end = time.monotonic() + 120
    while not report.exists() and handle.is_alive() and time.monotonic() < end:
        time.sleep(0.1)
    if not report.exists():
        handle.kill()
        raise AssertionError((workdir / "worker.err").read_text()[-2000:])
    return handle, json.loads(report.read_text()), workdir


def _gone(pid):
    try:
        status = open(f"/proc/{pid}/status").read()
    except FileNotFoundError:
        return True
    return "\nState:\tZ" in status


def test_worker_environment_is_minimal(tmp_path, monkeypatch):
    handle, report, workdir = _probe(tmp_path, monkeypatch)
    try:
        env = dict(kv.split("=", 1) for kv in report["environ"].split("\0") if "=" in kv)
        assert set(env) <= {"PATH", "HOME", "LANG", "TMPDIR", "PYTHONDONTWRITEBYTECODE",
                            "OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS",
                            "NUMEXPR_NUM_THREADS", "AI_TRAIN_THREADS", "AI_TRAIN_MAX_MEMORY_MB"}
        for v in SECRETS.values():
            assert v not in report["environ"]
        assert env["HOME"] == env["TMPDIR"] == str(workdir)
        assert report["params"] == {"mode": "probe"}  # params arrive on stdin
        assert report["argv"][1:] == [str(workdir)]
    finally:
        handle.kill()
        handle.join(10)


def test_worker_threads_are_bounded(tmp_path, monkeypatch):
    handle, report, _ = _probe(tmp_path, monkeypatch, threads=3)
    try:
        assert report["interop"] == 1 and report["torch_threads"] == 3
        assert report["pools"] and all(n <= 3 for n in report["pools"])
        assert report["pools_in_run"] and all(n <= 3 for n in report["pools_in_run"])
    finally:
        handle.kill()
        handle.join(10)


def test_terminate_kills_the_whole_process_group(tmp_path, monkeypatch):
    handle, report, _ = _probe(tmp_path, monkeypatch)
    grandchild = report["grandchild"]
    assert not _gone(grandchild)
    handle.terminate()
    handle.join(10)
    assert not handle.is_alive() and handle.exitcode == -signal.SIGTERM
    end = time.monotonic() + 10
    while not _gone(grandchild) and time.monotonic() < end:
        time.sleep(0.1)
    assert _gone(grandchild)


def test_worker_exits_when_the_server_is_killed(tmp_path):
    """A parent that dies by SIGKILL (no cleanup) must not leave a training worker behind."""
    script = (
        "import sys, time\n"
        "from inference_server import training_job\n"
        "training_job.WORKER_MODULE = 'tests.train_probe_worker'\n"
        f"h = training_job.popen_launcher({str(tmp_path)!r}, {{'mode': 'probe'}}, 1, 0)\n"
        "print(h.proc.pid, flush=True)\n"
        "time.sleep(600)\n")
    parent = subprocess.Popen([sys.executable, "-c", script], cwd=ROOT, stdout=subprocess.PIPE,
                              env={k: v for k, v in os.environ.items()
                                   if k in ("PATH", "PYTHONPATH", "HOME")})
    worker = int(parent.stdout.readline())
    end = time.monotonic() + 120
    while not (tmp_path / "probe.json").exists() and time.monotonic() < end:
        time.sleep(0.1)
    grandchild = json.loads((tmp_path / "probe.json").read_text())["grandchild"]
    parent.kill()
    parent.wait()
    end = time.monotonic() + 15
    while not (_gone(worker) and _gone(grandchild)) and time.monotonic() < end:
        time.sleep(0.2)
    assert _gone(worker) and _gone(grandchild)


# --- logs never carry a presigned URL --------------------------------------------------------


class _Storage(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path.startswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:1/x?{SECRET}")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Length", "5")
        self.end_headers()
        self.wfile.write(b"hello")

    def do_PUT(self):
        self.rfile.read(int(self.headers["Content-Length"]))
        self.send_response(403 if self.path.startswith("/denied") else 200)
        self.send_header("Content-Length", "0")
        self.end_headers()


@pytest.fixture
def real_storage(monkeypatch):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Storage)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    host = f"127.0.0.1:{srv.server_address[1]}"
    monkeypatch.setenv("AI_BUNDLE_HOSTS", host)
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    yield host
    srv.shutdown()


def _exercise(controller, host, tmp_path):
    job = training_job.Job("j")
    hosts = training_job.allowed_hosts()
    results = []
    with controller._client() as client:
        for path, op in (("ok", "get"), ("ok", "put"), ("redirect", "get"), ("denied", "put")):
            url = training_job.check_url(f"http://{host}/{path}/k?{SECRET}&X-Amz-Credential=AKIA",
                                         hosts, "x")
            try:
                if op == "get":
                    controller._download(client, url, str(tmp_path / f"{path}.bin"), job,
                                         time.monotonic() + 30)
                else:
                    controller._upload(client, url, b"A" * 100, "manifest.json")
                results.append("ok")
            except training_job.JobError as e:
                results.append(str(e))
        url = training_job.check_url(f"http://{host}/ok/k?{SECRET}", hosts, "x")
    refused = training_job.check_url(f"http://127.0.0.1:1/k?{SECRET}", {"127.0.0.1:1"}, "x")
    with controller._client() as client:
        try:
            controller._upload(client, refused, b"A", "manifest.json")
        except training_job.JobError as e:
            results.append(str(e))
    return results


def _assert_no_secret(caplog):
    text = caplog.text + "".join(r.getMessage() for r in caplog.records)
    assert "deadbeef" not in text and "X-Amz-Signature=" not in text and "AKIA" not in text


def test_presigned_urls_never_reach_the_logs(real_storage, caplog, tmp_path):
    caplog.set_level(logging.DEBUG)
    controller = training_job.JobController(tmp_base=str(tmp_path))
    training_job.install_log_redaction()
    results = _exercise(controller, real_storage, tmp_path)
    assert results[:2] == ["ok", "ok"] and "redirect" in results[2] and "HTTP 403" in results[3]
    assert "ConnectError" in results[4]
    assert logging.getLogger("httpx").getEffectiveLevel() >= logging.WARNING
    assert logging.getLogger("httpcore").getEffectiveLevel() >= logging.WARNING
    _assert_no_secret(caplog)


def test_log_filter_redacts_even_when_httpx_logs_at_debug(real_storage, caplog, tmp_path,
                                                          monkeypatch):
    """Task 6b or an operator may lower the httpx level: the root-handler filter still holds."""
    caplog.set_level(logging.DEBUG)
    training_job.install_log_redaction()
    for name in ("httpx", "httpcore"):  # lowered after the install, as a later change might
        monkeypatch.setattr(logging.getLogger(name), "level", logging.DEBUG)
    controller = training_job.JobController(tmp_base=str(tmp_path))
    _exercise(controller, real_storage, tmp_path)
    assert any("HTTP Request" in r.getMessage() for r in caplog.records)  # it did log
    _assert_no_secret(caplog)
    logging.getLogger("inference_server").warning("x http://h:1/p?%s y", SECRET, exc_info=False)
    _assert_no_secret(caplog)


@pytest.mark.parametrize("message", [
    f"PUT http://h:9000/b/k?{SECRET} done", f"'https://h/k?a=b&{SECRET}'",
    "X-Amz-Signature=abc&X-Amz-Credential=AKIA%2F", "see https://h:1/x#frag?y",
])
def test_redaction_filter(message):
    record = logging.LogRecord("x", logging.INFO, __file__, 1, "%s", (message,), None)
    assert training_job.RedactUrls().filter(record)
    out = record.getMessage()
    assert "deadbeef" not in out and "AKIA" not in out and "a=b" not in out and "frag" not in out


# --- request limits found by the review ------------------------------------------------------


@pytest.mark.parametrize("raw", [
    '"x": NaN', '"x": Infinity', '"x": -Infinity', '"x": 1e999', '"x": ' + "9" * 5000,
    '"x": ' + "[" * 40 + "]" * 40,
])
def test_campaign_profile_must_be_strict_json(train, env, raw):
    client, _, _, launches, _ = train()
    text = json.dumps(body()).replace('"min_members": 3', raw)
    r = client.post("/v2/train", content=text, headers={**env, "Content-Type": "application/json"})
    assert r.status_code == 422, r.text
    assert not launches


def test_dataset_row_cap_matches_the_group_ceiling():
    assert dataset_mod.MAX_ROWS == 8000


def test_too_many_rows_are_refused_before_loading(tmp_path, monkeypatch):
    n = dataset_mod.MAX_ROWS + 1
    data = make_dataset(embeddings=np.zeros((n, 1), np.float32),
                        campaign_embeddings=np.zeros((n, 1), np.float32),
                        folders=np.repeat(np.array(FOLDERS[:1]), n),
                        case_ids=np.arange(n, dtype=np.int64))

    def no_load(*a, **k):
        raise AssertionError("arrays loaded")

    monkeypatch.setattr(dataset_mod.np, "load", no_load)
    with pytest.raises(dataset_mod.DatasetError, match="rows"):
        dataset_mod.read_dataset(_write(tmp_path, data))


def test_too_many_rows_fail_the_job_without_grouping(train, env, monkeypatch):
    n = dataset_mod.MAX_ROWS + 1
    data = make_dataset(embeddings=np.zeros((n, 1), np.float32),
                        campaign_embeddings=np.zeros((n, 1), np.float32),
                        folders=np.repeat(np.array(FOLDERS[:1]), n),
                        case_ids=np.arange(n, dtype=np.int64))

    def no_groups(*a, **k):
        raise AssertionError("groups computed")

    monkeypatch.setattr(training_worker, "near_duplicate_groups", no_groups)
    client, _, storage, *_ = train(storage=Storage(dataset=data))
    client.post("/v2/train", json=body(), headers=env)
    state = wait(client, env)
    assert state["state"] == "failed" and "rows" in state["error"] and not storage.puts


def test_report_flags_final_temperatures_at_a_bound(train, env):
    client, *_ = train()
    client.post("/v2/train", json=body(), headers=env)
    report = wait(client, env)["report"]
    assert set(report["temperature_at_bound"]) == {"hierarchy", "knn"}
    assert all(isinstance(v, bool) for v in report["temperature_at_bound"].values())
    assert set(report["temperature"]) == {"hierarchy", "knn"}
    assert all(math.isfinite(v) for v in report["temperature"].values())


def test_read_timeout_is_short():
    assert training_job.TIMEOUT.read <= 10


# --- dataset reader --------------------------------------------------------------------------


def _write(tmp_path, data, name="d.npz"):
    p = tmp_path / name
    p.write_bytes(data)
    return p


def test_read_dataset_round_trip(tmp_path):
    d = dataset_mod.read_dataset(_write(tmp_path, make_dataset()))
    assert d.embeddings.shape == (80, 16) and d.embeddings.dtype == np.float32
    assert d.campaign_embeddings.shape == (80, 64)
    assert list(d.folders[:10]) == [FOLDERS[0]] * 10 and d.case_ids[0] == 1


@pytest.mark.parametrize("override, why", [
    ({"case_ids": None}, "arrays"),
    ({"extra": np.zeros(3)}, "arrays"),
    ({"case_ids": np.arange(80, dtype=np.int32)}, "case_ids"),
    ({"case_ids": np.zeros(80, dtype=np.int64)}, "case_ids"),
    ({"case_ids": np.arange(79, dtype=np.int64)}, "case_ids"),
    ({"embeddings": np.zeros((80, 16), dtype=np.float64)}, "embeddings"),
    ({"embeddings": np.full((80, 16), np.nan, dtype=np.float32)}, "embeddings"),
    ({"embeddings": np.zeros((80,), dtype=np.float32)}, "embeddings"),
    ({"campaign_embeddings": np.zeros((79, 64), dtype=np.float32)}, "campaign_embeddings"),
    ({"folders": np.array(["9_EVIL"] * 80)}, "folders"),
    ({"folders": np.zeros(80, dtype=np.int64)}, "folders"),
    ({"folders": np.array(["x" * 300] * 80)}, "folders"),
])
def test_read_dataset_refuses_bad_arrays(tmp_path, override, why):
    with pytest.raises(dataset_mod.DatasetError, match=why):
        dataset_mod.read_dataset(_write(tmp_path, make_dataset(**override)))


def test_read_dataset_refuses_pickles(tmp_path):
    buf = io.BytesIO()
    obj = np.array([{"a": 1}] * 80, dtype=object)
    np.savez(buf, embeddings=np.zeros((80, 16), np.float32),
             campaign_embeddings=np.zeros((80, 64), np.float32), folders=obj,
             case_ids=np.arange(80, dtype=np.int64))
    with pytest.raises(dataset_mod.DatasetError):
        dataset_mod.read_dataset(_write(tmp_path, buf.getvalue()))


def test_read_dataset_refuses_compressed_and_oversized(tmp_path, monkeypatch):
    buf = io.BytesIO()
    np.savez_compressed(buf, embeddings=np.zeros((80, 16), np.float32))
    with pytest.raises(dataset_mod.DatasetError):
        dataset_mod.read_dataset(_write(tmp_path, buf.getvalue()))
    monkeypatch.setattr(dataset_mod, "MAX_DATASET_BYTES", 100)
    with pytest.raises(dataset_mod.DatasetError, match="cap"):
        dataset_mod.read_dataset(_write(tmp_path, make_dataset(), "e.npz"))


def test_read_dataset_refuses_symlinks_and_garbage(tmp_path):
    real = _write(tmp_path, make_dataset())
    os.symlink(real, tmp_path / "link.npz")
    with pytest.raises(dataset_mod.DatasetError):
        dataset_mod.read_dataset(tmp_path / "link.npz")
    with pytest.raises(dataset_mod.DatasetError):
        dataset_mod.read_dataset(_write(tmp_path, b"PK\x03\x04garbage", "g.npz"))
