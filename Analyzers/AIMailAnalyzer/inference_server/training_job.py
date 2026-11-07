"""Single-job training controller behind POST /v2/train (Plan E, Task 6).

One job at a time, state in memory only (a restart forgets it; Django then sees 404 and fails the
row). Per job, a monitor thread:
1. makes a private 0700 directory (mkdtemp) and downloads the dataset into it;
2. starts `python -m inference_server.training_worker <dir>` with subprocess.Popen in a new
   session, an explicit minimal environment (see popen_launcher) and the validated params as JSON
   on stdin: no URL, no token, no storage key. The worker runs as the same UID, so this keeps
   secrets out of it by construction but is not a boundary against code running inside it (see
   training_worker's docstring);
3. reads the worker's progress file, enforces cancel and the wall-time limit (SIGTERM to the
   worker's process group, then SIGKILL after a grace period), reads the result file;
4. PUTs each bundle file to its own presigned URL, manifest last;
5. removes the directory, on every exit path. Leftovers of a crashed server are swept at start.

URLs (Ruling E9): http or https, no userinfo, no fragment, printable ASCII only, and the
host:port (as parsed, the scheme's default port when none is given) must be in AI_BUNDLE_HOSTS. The allow-list is the
control: names are compared as strings, nothing is resolved, so an allowed name points wherever
the deployment's DNS says. Internationalised host names never pass (fails closed): a non-ASCII
URL is refused outright, and for a punycode host (xn--...) httpx reports the decoded name, which
differs from urlsplit's, so the parsers disagree; use an ASCII name or an IP address. Redirects are
never followed, proxies and .netrc are ignored, the dataset must announce its Content-Length, be
at most 200 MB and match it exactly, and is read raw (no content decoding). Errors name the step,
never a URL or query string.
"""
import hashlib
import json
import logging
import math
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from typing import Literal, Optional
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator

from training.bundle import (
    BUNDLE_FILES, JSON_CAPS, MANIFEST, BundleError, json_shape_ok, read_file_capped,
)
from training.recipe import PREPROCESSING_VERSION_TOKENS, PREPROCESSING_VERSION_WORDS90

from . import training_worker

logger = logging.getLogger("inference_server.training")

# Presigned URLs carry their credential in the query string. httpx logs every request line at INFO
# ("HTTP Request: PUT http://...?X-Amz-Signature=..."): its loggers stay at WARNING (Task 6b's
# reload path must not lower them), and RedactUrls strips query strings from any record that does
# get through, on the httpx/httpcore loggers and on every root handler. It covers the loggers this
# code uses and handlers on root/httpx/httpcore; not logging.lastResort, nor handlers that other
# loggers attach for themselves (records that do not propagate to root).
_URL_QUERY = re.compile(r"(https?://[^\s?#'\"<>]*)[?#][^\s'\"<>]*", re.IGNORECASE)
_AMZ_PARAM = re.compile(r"X-Amz-[A-Za-z-]+=[^&\s'\"<>]*", re.IGNORECASE)


def redact(text: str) -> str:
    return _AMZ_PARAM.sub("X-Amz-(redacted)", _URL_QUERY.sub(r"\1?(redacted)", text))


class RedactUrls(logging.Filter):
    """Rewrites a record whose message or traceback holds a URL query string or an X-Amz-*
    parameter. Never drops a record."""

    def filter(self, record):
        try:
            msg = record.getMessage()
        except Exception:  # noqa: BLE001 - a broken record is the formatter's business
            return True
        clean = redact(msg)
        if clean != msg:
            record.msg, record.args = clean, None
        if record.exc_info and not record.exc_text:
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        if record.exc_text:
            record.exc_text = redact(record.exc_text)
        return True


_REDACT = RedactUrls()


def install_log_redaction():
    """Idempotent: the filter on the httpx/httpcore loggers and on the root handlers present now
    (called at import and again when a job starts, after the server configured logging)."""
    for name in ("httpx", "httpcore"):
        lg = logging.getLogger(name)
        if lg.level == logging.NOTSET or lg.level < logging.WARNING:
            lg.setLevel(logging.WARNING)
        if _REDACT not in lg.filters:
            lg.addFilter(_REDACT)
    for h in logging.getLogger().handlers:
        if _REDACT not in h.filters:
            h.addFilter(_REDACT)


install_log_redaction()

JOB_ID_PATTERN = r"^[A-Za-z0-9_-]{1,64}$"
JOB_ID_RE = re.compile(JOB_ID_PATTERN)
LABEL_PATTERN = r"^[A-Za-z0-9._:/+-]{1,128}$"  # ids, digests, revisions written to the manifest
UPLOAD_NAMES = (*BUNDLE_FILES, MANIFEST)  # upload order: the manifest last
MAX_DOWNLOAD = 200 * 2**20  # Ruling E9
MAX_BODY = 64 * 1024  # request body of POST /v2/train
MAX_URL = 4096
MAX_RESULT = 1024 * 1024
MAX_JOBS_KEPT = 50
TMP_PREFIX = "ai-train-"
TERMINAL = frozenset({"succeeded", "failed", "cancelled"})
_URL_CHARS = re.compile(r"[\x21-\x7e]+")  # printable ASCII, no space or control character
DEFAULT_PORTS = {"http": 80, "https": 443}
# A cancel or the wall-time limit is checked between chunks: during a stalled download it waits up
# to the read timeout and then ends as failed (ReadTimeout), not cancelled.
TIMEOUT = httpx.Timeout(connect=5.0, read=10.0, write=60.0, pool=5.0)


class JobError(Exception):
    """A failure reason safe to store and return: never a URL, query string or data."""


class _Cancelled(Exception):
    pass


# --- request ---------------------------------------------------------------------------------

Label = Field(pattern=LABEL_PATTERN)


MAX_ENCODER_BYTES = 4 << 30  # an encoder directory larger than this gets no hash


def encoder_digest(path: str, *, cap: int = MAX_ENCODER_BYTES) -> Optional[str]:
    """SHA-256 over every regular file under path (symlinks are not followed), in sorted relative
    POSIX name order: name, NUL, size, NUL, bytes. None when the path is missing or unreadable or
    the files exceed cap. The training job records it as the manifest's encoder_hash and reload
    compares it, so a bundle trained with another encoder is refused."""
    files = []
    try:
        for root, dirs, names in os.walk(path):  # followlinks=False: linked dirs are not entered
            dirs.sort()
            for name in names:
                full = os.path.join(root, name)
                st = os.lstat(full)
                if stat.S_ISREG(st.st_mode):
                    files.append((os.path.relpath(full, path).replace(os.sep, "/"), full, st.st_size))
        if not files or sum(f[2] for f in files) > cap:
            return None
        digest = hashlib.sha256()
        for rel, full, size in sorted(files):
            digest.update(f"{rel}\0{size}\0".encode())
            with open(full, "rb", opener=lambda p, f: os.open(p, f | os.O_NOFOLLOW)) as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


class TrainParams(BaseModel):
    """Everything the worker gets besides the dataset. Strings land in the manifest. The server
    adds encoder_hash itself (encoder_digest of its own encoder); a caller cannot send one."""
    model_config = ConfigDict(extra="forbid", strict=True)
    version_id: str = Field(pattern=JOB_ID_PATTERN)
    seed: int = Field(ge=0, le=2**31 - 1)
    repeats: int = Field(default=3, ge=1, le=5)
    epochs: int = Field(default=30, ge=1, le=100)
    baseline: Literal["legacy", "candidate"]
    preprocessing_version: Literal[PREPROCESSING_VERSION_TOKENS, PREPROCESSING_VERSION_WORDS90] = \
        PREPROCESSING_VERSION_TOKENS
    parent_version: Optional[str] = Field(default=None, pattern=JOB_ID_PATTERN)
    ledger_digest: str = Label
    campaign_refs_digest: str = Label
    encoder_id: str = Label
    trainer_revision: str = Label
    campaign_profile: dict  # copied into the bundle as is (spec section 3)

    @field_validator("campaign_profile")
    @classmethod
    def _profile(cls, v):
        # strict JSON within the bundle's limits: NaN, Infinity and 1e999 (parsed as inf) are
        # refused here rather than when the finished bundle is written
        try:
            size = len(json.dumps(v, allow_nan=False))
        except (ValueError, TypeError, RecursionError):
            raise ValueError("campaign_profile must be strict JSON") from None
        if size > JSON_CAPS["campaign_profile.json"] or not json_shape_ok(v):
            raise ValueError("campaign_profile too large or nested too deeply")
        d = v.get("distance_threshold")
        if isinstance(d, bool) or not isinstance(d, (int, float)) or not 0 < d < 1:
            raise ValueError("distance_threshold must be a number in (0, 1)")
        return v


class TrainRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    job_id: str = Field(pattern=JOB_ID_PATTERN)
    dataset_url: str = Field(max_length=MAX_URL)
    bundle_urls: dict[str, str]
    params: TrainParams

    @field_validator("bundle_urls")
    @classmethod
    def _names(cls, v):
        if set(v) != set(UPLOAD_NAMES):
            raise ValueError("bundle_urls must name exactly the bundle files")
        if any(len(u) > MAX_URL for u in v.values()):
            raise ValueError("URL too long")
        return v


# --- URLs ------------------------------------------------------------------------------------

def _host_key(hostname, port):
    return f"{hostname}:{port}"


def allowed_hosts() -> set:
    """AI_BUNDLE_HOSTS: comma separated host:port entries; anything else is ignored. Empty or
    unset refuses every URL."""
    hosts = set()
    for entry in os.environ.get("AI_BUNDLE_HOSTS", "").split(","):
        entry = entry.strip().lower()
        if not entry or not _URL_CHARS.fullmatch(entry) or "/" in entry or "@" in entry:
            continue
        try:
            p = urlsplit("//" + entry)
            port = p.port
        except ValueError:
            continue
        if p.hostname and port:
            hosts.add(_host_key(p.hostname, port))
    return hosts


def check_url(url: str, hosts: set, what: str) -> httpx.URL:
    """Validate with both urlsplit and httpx (the parser that sends the request): they must agree
    on scheme, host and port, so a parser trick cannot pass one check and reach another host."""
    if not isinstance(url, str) or len(url) > MAX_URL or not _URL_CHARS.fullmatch(url) \
            or "\\" in url or "#" in url:  # presigned URLs carry no fragment
        raise JobError(f"{what}: URL not accepted")
    try:
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        if scheme not in DEFAULT_PORTS:
            raise JobError(f"{what}: scheme not allowed")
        if "@" in parts.netloc or parts.username is not None or parts.password is not None:
            raise JobError(f"{what}: credentials in URL not allowed")
        port = parts.port or DEFAULT_PORTS[scheme]
        hostname = parts.hostname
        u = httpx.URL(url)
    except JobError:
        raise
    except Exception:  # noqa: BLE001 - ValueError, httpx.InvalidURL: never echo the URL
        raise JobError(f"{what}: URL not accepted") from None
    if (not hostname or u.scheme != scheme or u.userinfo or u.host != hostname
            or (u.port or DEFAULT_PORTS[scheme]) != port):
        raise JobError(f"{what}: URL not accepted")
    if _host_key(hostname, port) not in hosts:
        raise JobError(f"{what}: host not allowed")
    return u


# --- worker files ----------------------------------------------------------------------------

def _read_small(path, cap) -> Optional[bytes]:
    """A regular file (no symlink) of at most cap bytes, else None."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        data = os.read(fd, cap + 1)
        return data if len(data) <= cap else None
    finally:
        os.close(fd)


def _log_worker_tail(workdir):
    """The end of the worker's stderr, for the operator (the job error stays the exit code)."""
    path = os.path.join(workdir, WORKER_LOG)
    try:
        with open(path, "rb") as fh:
            fh.seek(max(0, os.path.getsize(path) - 2048))
            tail = fh.read().decode("utf-8", "replace")
    except OSError:
        return
    logger.warning("training worker failed; end of its stderr:\n%s", tail)


def _read_progress(workdir) -> Optional[float]:
    """The worker's percent, clamped to [0, 100]; None for anything that is not one number."""
    raw = _read_small(os.path.join(workdir, training_worker.OUT, training_worker.PROGRESS), 16)
    if not raw or not re.fullmatch(rb"[0-9eE.+-]{1,16}", raw):
        return None
    try:
        v = float(raw)
    except ValueError:
        return None
    return min(max(v, 0.0), 100.0) if math.isfinite(v) else None


WORKER_MODULE = "inference_server.training_worker"
PACKAGE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
THREAD_ENV = ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS", "NUMEXPR_NUM_THREADS")
WORKER_LOG = "worker.err"


class PopenHandle:
    """multiprocessing.Process-like view of the worker. Signals go to its whole process group
    (start_new_session=True made it the leader), so anything it started dies with it.
    exitcode is negative for a signal, like multiprocessing's."""

    def __init__(self, proc):
        self.proc = proc

    @property
    def exitcode(self):
        return self.proc.poll()

    def is_alive(self):
        return self.proc.poll() is None

    def join(self, timeout=None):
        try:
            self.proc.wait(timeout)
        except subprocess.TimeoutExpired:
            pass

    def _signal(self, sig):
        try:
            os.killpg(self.proc.pid, sig)
        except (ProcessLookupError, PermissionError):
            pass

    def terminate(self):
        self._signal(signal.SIGTERM)

    def kill(self):
        self._signal(signal.SIGKILL)


def worker_env(workdir, threads, max_memory_mb) -> dict:
    """The worker's whole environment. Nothing is inherited from the server (no token, no storage
    or database secret, no proxy, no PYTHONPATH or LD_PRELOAD); TMPDIR keeps scratch files inside
    the job directory, which is removed at the end."""
    env = {"PATH": os.environ.get("PATH") or os.defpath, "HOME": workdir, "TMPDIR": workdir,
           "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1",
           "AI_TRAIN_THREADS": str(threads), "AI_TRAIN_MAX_MEMORY_MB": str(max_memory_mb)}
    env.update({k: str(threads) for k in THREAD_ENV})
    return env


def popen_launcher(workdir, params, threads, max_memory_mb):
    """Default launcher. No shell; the module name is a constant and the params travel as JSON on
    stdin (at most training_worker.MAX_PARAMS bytes); stdout and stderr go to a 0600 file in the
    job directory."""
    data = json.dumps(params, allow_nan=False).encode()
    if len(data) > training_worker.MAX_PARAMS:
        raise JobError("params too large")
    fd = os.open(os.path.join(workdir, WORKER_LOG), os.O_WRONLY | os.O_CREAT | os.O_EXCL
                 | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as log:
        proc = subprocess.Popen([sys.executable, "-s", "-m", WORKER_MODULE, workdir],
                                cwd=PACKAGE_ROOT, env=worker_env(workdir, threads, max_memory_mb),
                                stdin=subprocess.PIPE, stdout=log, stderr=log, close_fds=True,
                                start_new_session=True)
    try:
        proc.stdin.write(data)  # below the pipe buffer: never blocks
        proc.stdin.close()
    except BrokenPipeError:
        pass  # the worker died first; its exit code tells
    return PopenHandle(proc)


# --- jobs ------------------------------------------------------------------------------------

@dataclass
class Job:
    job_id: str
    state: str = "queued"
    progress: float = 0.0
    report: Optional[dict] = None
    error: Optional[str] = None
    cancel: threading.Event = field(default_factory=threading.Event)
    started: float = field(default_factory=time.monotonic)

    def view(self) -> dict:
        return {"job_id": self.job_id, "state": self.state, "progress": round(self.progress, 1),
                "report": self.report, "error": self.error}


def default_base_dir() -> str:
    """Where job and reload directories go: AI_TRAIN_TMPDIR, else the system temp dir (read at
    each use, not at import)."""
    return os.environ.get("AI_TRAIN_TMPDIR") or tempfile.gettempdir()


def sweep(base, prefix):
    """Remove leftovers named prefix* under base: only real directories owned by this uid, never
    through a symlink. Call it only where no live directory of that prefix can exist."""
    try:
        names = os.listdir(base)
    except OSError:
        return
    for name in names:
        path = os.path.join(base, name)
        try:
            st = os.lstat(path)
        except OSError:
            continue
        if name.startswith(prefix) and stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid():
            shutil.rmtree(path, ignore_errors=True)


def make_client(transport=None) -> httpx.Client:
    """The only HTTP client for presigned URLs: no redirects, no proxy or .netrc from the
    environment, short timeouts."""
    return httpx.Client(transport=transport, follow_redirects=False, trust_env=False,
                        timeout=TIMEOUT)


def download(client, url, path, *, cap, what, check=lambda: None):
    """GET url (an httpx.URL from check_url) into a new 0600 file at path. The response must be a
    200 with an identity encoding and a Content-Length of at most cap, and the raw body must match
    it exactly; the cap is also enforced while streaming. check() runs after each chunk (cancel,
    deadline). Errors are JobError naming `what`, never the URL."""
    try:
        with client.stream("GET", url, headers={"Accept-Encoding": "identity"}) as r:
            if 300 <= r.status_code < 400:
                raise JobError(f"{what}: redirect refused")
            if r.status_code != 200:
                raise JobError(f"{what}: HTTP {r.status_code}")
            if r.headers.get("content-encoding", "identity").strip().lower() != "identity":
                raise JobError(f"{what}: content encoding refused")
            length = r.headers.get("content-length", "")
            if not re.fullmatch(r"[0-9]{1,12}", length):
                raise JobError(f"{what}: missing or invalid content length")
            expected = int(length)
            if expected > cap:
                raise JobError(f"{what}: size above the cap")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as fh:
                got = 0
                for chunk in r.iter_raw():
                    got += len(chunk)
                    if got > cap:
                        raise JobError(f"{what}: size above the cap")
                    if got > expected:
                        raise JobError(f"{what}: body longer than its content length")
                    fh.write(chunk)
                    check()
            if got != expected:
                raise JobError(f"{what}: body shorter than its content length")
    except httpx.HTTPError as e:
        raise JobError(f"{what}: {type(e).__name__}") from None


def _env_int(name, default, low):
    try:
        return max(low, int(os.environ.get(name, default)))
    except ValueError:
        return default


class JobController:
    def __init__(self, *, launcher=popen_launcher, transport=None, tmp_base=None,
                 grace_seconds=10.0, poll_seconds=0.5, encoder_hash=None):
        self.launcher = launcher
        self.encoder_hash = encoder_hash or (lambda: None)  # the loaded encoder's digest, or None
        self.transport = transport  # tests inject an httpx.MockTransport
        self.tmp_base = tmp_base  # None: AI_TRAIN_TMPDIR, else the system temp dir, at first use
        self.grace_seconds = grace_seconds
        self.poll_seconds = poll_seconds
        self.jobs: dict = {}
        self._lock = threading.Lock()
        self._swept = False

    def base_dir(self) -> str:
        return self.tmp_base or default_base_dir()

    def _sweep(self):
        """Job directories left by a server that died mid-job, removed at the first job (not at
        import). Safe only because the server runs as ONE process (a single uvicorn worker, see
        server.py): a second process would sweep a live job's directory, and the single-job
        lock would not span processes."""
        sweep(self.base_dir(), TMP_PREFIX)

    def _evict(self):
        """ponytail: keep the last MAX_JOBS_KEPT jobs; Django polls a job within minutes."""
        for job_id in [j for j, job in self.jobs.items() if job.state in TERMINAL]:
            if len(self.jobs) <= MAX_JOBS_KEPT:
                break
            del self.jobs[job_id]

    # -- API ---------------------------------------------------------------------------------

    def start(self, req: TrainRequest, encoder_hash: Optional[str] = None) -> tuple[int, dict]:
        """encoder_hash: the caller computes it (self.encoder_hash) outside the event loop."""
        install_log_redaction()
        with self._lock:
            if req.job_id in self.jobs:
                return 200, self.jobs[req.job_id].view()
            if any(j.state not in TERMINAL for j in self.jobs.values()):
                return 409, {"detail": "a training job is already running"}
            if not self._swept:  # no job runs yet in this process
                self._sweep()
                self._swept = True
            job = self.jobs[req.job_id] = Job(req.job_id)
            self._evict()
            if not encoder_hash:
                job.state, job.error = "failed", "encoder not loaded"
                return 202, job.view()
            try:
                hosts = allowed_hosts()
                dataset = check_url(req.dataset_url, hosts, "dataset download")
                uploads = {n: check_url(req.bundle_urls[n], hosts, f"bundle upload {n}")
                           for n in UPLOAD_NAMES}
            except JobError as e:
                job.state, job.error = "failed", str(e)
                return 202, job.view()
            params = {**req.params.model_dump(), "encoder_hash": encoder_hash}
            threading.Thread(target=self._run, args=(job, dataset, uploads, params),
                             daemon=True, name=f"ai-train-{req.job_id}").start()
            return 202, job.view()

    def get(self, job_id) -> Optional[dict]:
        job = self.jobs.get(job_id)
        return job.view() if job else None

    def cancel(self, job_id) -> Optional[dict]:
        job = self.jobs.get(job_id)
        if job is None:
            return None
        if job.state not in TERMINAL:
            job.cancel.set()
        return job.view()

    # -- the job -----------------------------------------------------------------------------

    def _client(self):
        return make_client(self.transport)

    def _checkpoint(self, job, deadline):
        if job.cancel.is_set():
            raise _Cancelled()
        if time.monotonic() > deadline:
            raise JobError("wall-time limit reached")

    def _run(self, job, dataset_url, uploads, params):
        deadline = job.started + _env_int("AI_TRAIN_MAX_SECONDS", 4 * 3600, 1)
        threads = _env_int("AI_TRAIN_THREADS", 2, 1)
        max_memory_mb = _env_int("AI_TRAIN_MAX_MEMORY_MB", 0, 0)
        workdir, handle = None, None
        final = ("failed", None, "internal error")  # if a BaseException escapes
        try:
            workdir = tempfile.mkdtemp(prefix=TMP_PREFIX, dir=self.base_dir())  # mode 0700
            with self._client() as client:
                self._checkpoint(job, deadline)
                job.state = "running"
                self._download(client, dataset_url, os.path.join(workdir, training_worker.DATASET),
                               job, deadline)
                self._checkpoint(job, deadline)
                handle = self.launcher(workdir, params, threads, max_memory_mb)
                while handle.is_alive():
                    handle.join(self.poll_seconds)
                    pct = _read_progress(workdir)
                    if pct is not None:
                        job.progress = pct * 0.98  # the last 2% are the uploads
                    self._checkpoint(job, deadline)
                if handle.exitcode != 0:
                    _log_worker_tail(workdir)
                    raise JobError(f"worker exited with code {handle.exitcode}")
                result, blobs = self._collect(workdir)
                for name in UPLOAD_NAMES:
                    self._checkpoint(job, deadline)
                    self._upload(client, uploads[name], blobs[name], name)
            report = {**result["summary"], "manifest_sha256": result["manifest_sha256"],
                      "encoder_hash": params["encoder_hash"], "uploaded": list(UPLOAD_NAMES)}
            final = ("succeeded", report, None)
        except _Cancelled:
            final = ("cancelled", None, None)
        except JobError as e:
            final = ("failed", None, str(e))
        except Exception as e:  # noqa: BLE001 - the type only: messages may carry a URL
            logger.error("training job %s failed: %s", job.job_id, type(e).__name__)
            final = ("failed", None, f"internal error: {type(e).__name__}")
        finally:
            # the state turns terminal only once the worker is gone and the directory removed, so
            # a new job cannot start beside a dying one
            try:
                if handle is not None:
                    if handle.is_alive():
                        self._stop(handle)
                    handle.kill()  # anything left in the worker's process group
            finally:
                if workdir:
                    shutil.rmtree(workdir, ignore_errors=True)
                state, report, error = final
                if state == "succeeded":
                    job.progress = 100.0
                job.report, job.error, job.state = report, error, state

    def _stop(self, handle):
        handle.terminate()
        handle.join(self.grace_seconds)
        if handle.is_alive():
            handle.kill()
            handle.join(self.grace_seconds)

    def _download(self, client, url, path, job, deadline):
        download(client, url, path, cap=MAX_DOWNLOAD, what="dataset download",
                 check=lambda: self._checkpoint(job, deadline))

    def _upload(self, client, url, data, name):
        what = f"bundle upload {name}"
        try:
            with client.stream("PUT", url, content=data,
                               headers={"Content-Length": str(len(data))}) as r:
                if 300 <= r.status_code < 400:  # the body is never read
                    raise JobError(f"{what}: redirect refused")
                if not 200 <= r.status_code < 300:
                    raise JobError(f"{what}: HTTP {r.status_code}")
        except httpx.HTTPError as e:
            raise JobError(f"{what}: {type(e).__name__}") from None

    def _collect(self, workdir):
        """The worker's result and the bundle bytes. The pin returned is the parent's own SHA-256
        of the manifest bytes it uploads, and it must equal the worker's."""
        out = os.path.join(workdir, training_worker.OUT)
        raw = _read_small(os.path.join(out, training_worker.RESULT), MAX_RESULT)
        try:
            result = json.loads(raw)
        except (TypeError, ValueError):
            raise JobError("worker left no readable result") from None
        if not isinstance(result, dict):
            raise JobError("worker left no readable result")
        if "error" in result:
            raise JobError(f"training: {str(result['error'])[:500]}")
        if not isinstance(result.get("summary"), dict) \
                or not isinstance(result.get("manifest_sha256"), str):
            raise JobError("worker result incomplete")
        blobs, spent = {}, 0
        try:
            root = os.open(os.path.join(out, training_worker.BUNDLE),
                           os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError:
            raise JobError("worker left no bundle") from None
        try:
            heads = os.open("heads", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
            try:
                for name in UPLOAD_NAMES:
                    fd, base = (heads, name[6:]) if name.startswith("heads/") else (root, name)
                    blobs[name], spent = read_file_capped(fd, base, name, spent)
            finally:
                os.close(heads)
        except BundleError as e:
            raise JobError(f"bundle not readable: {e}") from None
        except OSError as e:
            raise JobError(f"bundle not readable: {type(e).__name__}") from None
        finally:
            os.close(root)
        if hashlib.sha256(blobs[MANIFEST]).hexdigest() != result["manifest_sha256"]:
            raise JobError("manifest hash differs from the worker's")
        return result, blobs
