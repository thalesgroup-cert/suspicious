"""
Tests for the single-job training API (/v2/train): inference_server/training_job.py (controller,
URL rules, uploads), inference_server/training_worker.py (the subprocess) and
training/dataset.py (the downloaded dataset reader).

Most tests start the worker in-process through an injected launcher (a thread) with a tiny
recipe; storage is an httpx.MockTransport. Two tests use the real spawn launcher.
"""
import hashlib
import io
import os
import threading
import time

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

        def thread_launcher(target, args):
            launches.append(args)
            return ThreadHandle(target, args)

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
    real = training_worker.main

    def spy(workdir, *a):
        seen["mode"] = os.stat(workdir).st_mode & 0o777
        seen["dataset"] = os.stat(os.path.join(workdir, "dataset.npz")).st_mode & 0o777
        return real(workdir, *a)

    def launcher(target, args):
        return ThreadHandle(spy, args)

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

    def launcher(target, args):
        handles.append(ThreadHandle(target, args))
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
    client, _, storage, _, base = train(launcher=lambda target, args: DeadHandle(code))
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


def test_threads_are_bounded_in_the_worker(train, env, monkeypatch):
    monkeypatch.setenv("AI_TRAIN_THREADS", "3")
    seen = []
    monkeypatch.setattr(training_worker.torch, "set_num_threads", seen.append)
    got = {}

    def recipe(*a, threads, **k):
        got["threads"] = threads
        return tiny_recipe(*a, threads=threads, **k)

    client, _, _, launches, _ = train(recipe=recipe)
    client.post("/v2/train", json=body(), headers=env)
    assert wait(client, env)["state"] == "succeeded"
    assert seen[0] == 3 and got["threads"] == 3


def test_server_start_sweeps_leftover_job_dirs(tmp_path):
    (tmp_path / "ai-train-old").mkdir()
    (tmp_path / "ai-train-old" / "dataset.npz").write_bytes(b"x")
    (tmp_path / "keep").mkdir()
    training_job.JobController(tmp_base=str(tmp_path))
    assert sorted(os.listdir(tmp_path)) == ["keep"]


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


def test_worker_scrubs_credentials_from_its_environment(monkeypatch):
    monkeypatch.setenv("AI_INFERENCE_TOKEN", "t")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "s")
    training_worker._scrub_env()
    assert "AI_INFERENCE_TOKEN" not in os.environ and "AWS_SECRET_ACCESS_KEY" not in os.environ


# --- real subprocess -------------------------------------------------------------------------


def test_default_launcher_uses_spawn(monkeypatch):
    seen = {}

    class Ctx:
        def Process(self, **kw):
            seen.update(kw)

            class P:
                def start(self):
                    seen["started"] = True
            return P()

    monkeypatch.setattr(training_job.multiprocessing, "get_context",
                        lambda method: seen.setdefault("method", method) and Ctx())
    training_job.spawn_launcher(training_worker.main, ("d",))
    assert seen["method"] == "spawn" and seen["target"] is training_worker.main
    assert seen["daemon"] is True and seen["started"]


def test_real_spawned_worker_trains_a_bundle(make_client, tmp_path, monkeypatch, env):  # noqa: F811
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


def test_real_spawned_worker_killed_becomes_failed(make_client, tmp_path, monkeypatch,  # noqa: F811
                                                   env):
    def killing_launcher(target, args):
        p = training_job.spawn_launcher(target, args)
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
