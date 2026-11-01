"""The model bundle (spec section 3): five heads, calibration, kNN index, campaign profile and a
manifest holding a SHA-256 per file. The bytes come from object storage through a presigned URL,
so they are untrusted: read_bundle reads every file once into memory, verifies all hashes, and only
then parses the same bytes (no TOCTOU). It is the only place in the package that calls torch.load,
always with weights_only=True, and it accepts a head only if it is a plain dict of tensors that
fits a freshly built ResNetMLP. Errors are a single BundleError naming the file or field, never
file contents."""
import hashlib
import hmac
import io
import json
import math
import os
import errno
import re
import shutil
import stat
import tempfile
import zipfile
import zipfile
from dataclasses import dataclass

import numpy as np
import torch

from ResNetMLP import ResNetMLP
from training.gate import TIER_CUTOFF_KEYS
from training.recipe import HEADS, NUM_OUT, Heads, Knn

MANIFEST = "manifest.json"
BUNDLE_FILES = (
    *(f"heads/{h}.pth" for h in HEADS),
    "calibration.json", "knn_index.npz", "campaign_profile.json",
)
MAX_TOTAL = 100 * 2**20
MAX_FILE = 50 * 2**20
JSON_CAPS = {MANIFEST: 512 * 1024, "calibration.json": 64 * 1024, "campaign_profile.json": 256 * 1024}
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 20000
MAX_ZIP_MEMBERS = 64
ZIP_SLACK = 64 * 1024
TEMPERATURE_RANGE = (0.2, 30.0)  # Ruling E12 fit bounds
MAX_INPUT_DIM = 4096
TEMPERATURE_KEYS = ("hierarchy", "knn")
MANIFEST_FIELDS = (
    "version_id", "recipe_id", "preprocessing_version", "encoder_id", "encoder_hash",
    "ledger_digest", "campaign_refs_digest", "metrics", "gate", "parent_version",
    "trainer_revision", "input_dim",
)
_TOP = {MANIFEST, "calibration.json", "knn_index.npz", "campaign_profile.json", "heads"}


class BundleError(Exception):
    pass


@dataclass
class Bundle:
    heads: Heads
    calibration: dict
    knn: Knn
    campaign_profile: object
    manifest: dict
    input_dim: int


def _name(s):
    """Attacker-supplied names are shown only when they are plain."""
    s = str(s)
    return repr(s) if re.fullmatch(r"[A-Za-z0-9._/-]{1,60}", s) else "(unprintable name)"


# --- checks shared by write and read -------------------------------------------------------------

def _number(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def _check_calibration(cal):
    f = "calibration.json"
    if not isinstance(cal, dict):
        raise BundleError(f"{f}: not an object")
    t = cal.get("temperature")
    if not isinstance(t, dict) or set(t) != set(TEMPERATURE_KEYS):
        raise BundleError(f"{f}: temperature must be an object with hierarchy and knn")
    for k, v in t.items():
        if not _number(v) or not TEMPERATURE_RANGE[0] <= v <= TEMPERATURE_RANGE[1]:
            raise BundleError(f"{f}: temperature {k} must be within {TEMPERATURE_RANGE}")
    c = cal.get("tier_cutoffs")
    if (not isinstance(c, dict) or set(c) != set(TIER_CUTOFF_KEYS)
            or not all(_number(v) and 0 <= v <= 1.01 for v in c.values()) or c["medium"] > c["high"]):
        raise BundleError(f"{f}: tier_cutoffs must be {TIER_CUTOFF_KEYS} in [0, 1.01], medium <= high")
    if not isinstance(cal.get("held_out_groups"), (list, dict)):
        raise BundleError(f"{f}: held_out_groups missing")


def _check_manifest_fields(m):
    for k in MANIFEST_FIELDS:
        if k not in m:
            raise BundleError(f"{MANIFEST}: missing field {k}")
    d = m["input_dim"]
    if not isinstance(d, int) or isinstance(d, bool) or not 1 <= d <= MAX_INPUT_DIM:
        raise BundleError(f"{MANIFEST}: input_dim out of range")
    for k in ("version_id", "recipe_id", "preprocessing_version", "encoder_id", "encoder_hash",
              "ledger_digest", "campaign_refs_digest", "trainer_revision"):
        if not isinstance(m[k], str):
            raise BundleError(f"{MANIFEST}: {k} must be a string")
    if not isinstance(m["metrics"], dict) or not isinstance(m["gate"], dict):
        raise BundleError(f"{MANIFEST}: metrics and gate must be objects")
    if m["parent_version"] is not None and not isinstance(m["parent_version"], str):
        raise BundleError(f"{MANIFEST}: parent_version must be a string or null")


# --- write ---------------------------------------------------------------------------------------

def _json_bytes(obj, name):
    try:
        return json.dumps(obj, allow_nan=False, sort_keys=True).encode()
    except (ValueError, TypeError):
        raise BundleError(f"{name}: not strict JSON") from None


def _fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_bundle(dir, *, heads, calibration, knn, campaign_profile, manifest) -> str:
    """Write a bundle atomically: build it in a sibling temp dir, then rename. Hashes are computed
    here. Returns the SHA-256 hex of manifest.json (Ruling E14: the caller pins it). Refuses to
    replace a non-empty path."""
    dir = os.fspath(dir)
    _check_calibration(calibration)
    if set(heads.models) != set(HEADS):
        raise BundleError("heads: need exactly the five heads")
    manifest = {**manifest, "input_dim": heads.input_dim}
    _check_manifest_fields(manifest)

    blobs = {}
    for h in HEADS:
        buf = io.BytesIO()
        torch.save({k: v.detach().cpu().contiguous() for k, v in heads.models[h].state_dict().items()}, buf)
        blobs[f"heads/{h}.pth"] = buf.getvalue()
    blobs["calibration.json"] = _json_bytes(calibration, "calibration.json")
    try:
        case_ids = np.zeros(0, np.int64) if knn.case_ids is None else np.asarray(knn.case_ids, np.int64)
    except (ValueError, TypeError):
        raise BundleError("knn_index.npz: case ids must be integers") from None
    buf = io.BytesIO()
    np.savez(buf, embeddings=np.asarray(knn.embeddings, np.float32),
             label_ids=np.asarray(knn.labels, np.int64), case_ids=case_ids)
    blobs["knn_index.npz"] = buf.getvalue()
    blobs["campaign_profile.json"] = _json_bytes(campaign_profile, "campaign_profile.json")
    manifest["files"] = {k: hashlib.sha256(v).hexdigest() for k, v in blobs.items()}
    blobs[MANIFEST] = _json_bytes(manifest, MANIFEST)

    parent = os.path.dirname(os.path.abspath(dir))
    tmp = tempfile.mkdtemp(dir=parent, prefix=".bundle-")
    try:
        os.mkdir(os.path.join(tmp, "heads"))
        for rel, data in blobs.items():
            with open(os.path.join(tmp, rel), "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
        os.chmod(tmp, 0o755)
        os.chmod(os.path.join(tmp, "heads"), 0o755)
        _fsync_dir(os.path.join(tmp, "heads"))
        _fsync_dir(tmp)
        try:
            os.rename(tmp, dir)
        except OSError as e:
            if e.errno in (errno.ENOTEMPTY, errno.EEXIST, errno.ENOTDIR, errno.EISDIR):
                raise BundleError("bundle path already exists") from None
            raise
        _fsync_dir(parent)
        return hashlib.sha256(blobs[MANIFEST]).hexdigest()
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise


# --- read ----------------------------------------------------------------------------------------

def _open_dir(name, dir_fd=None):
    try:
        return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd)
    except OSError:
        raise BundleError(f"{_name(name)}: not a plain directory") from None


def _cap(rel):
    return min(MAX_FILE, JSON_CAPS.get(rel, MAX_FILE))


def _read_file(dir_fd, name, rel, spent):
    """Read one regular, single-link file from an open directory; return (bytes, new total)."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    except FileNotFoundError:
        raise BundleError(f"missing file {rel}") from None
    except OSError:
        raise BundleError(f"{rel}: cannot open") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise BundleError(f"{rel}: not a plain regular file")
        cap = _cap(rel)
        chunks, n = [], 0
        while True:
            chunk = os.read(fd, min(1 << 20, cap + 1 - n))
            if not chunk:
                break
            chunks.append(chunk)
            n += len(chunk)
            if n > cap:
                raise BundleError(f"{rel}: size above the per-file cap")
            if spent + n > MAX_TOTAL:
                raise BundleError("bundle size above the total cap")
        return b"".join(chunks), spent + n
    finally:
        os.close(fd)


def _shape_ok(v):
    """Depth and node-count bound for parsed JSON (iterative)."""
    stack, nodes = [(v, 0)], 0
    while stack:
        x, d = stack.pop()
        nodes += 1
        if d > MAX_JSON_DEPTH or nodes > MAX_JSON_NODES:
            return False
        if isinstance(x, dict):
            stack.extend((y, d + 1) for y in x.values())
        elif isinstance(x, list):
            stack.extend((y, d + 1) for y in x)
    return True


def _no_const(c):
    raise ValueError(c)


def _float(s):
    f = float(s)
    if not math.isfinite(f):
        raise ValueError(s)
    return f


def _no_dups(pairs):
    d = dict(pairs)
    if len(d) != len(pairs):
        raise ValueError("duplicate key")
    return d


def _parse_json(data, rel):
    try:
        obj = json.loads(data.decode("utf-8"), parse_constant=_no_const, parse_float=_float,
                         object_pairs_hook=_no_dups)
    except (ValueError, RecursionError):
        raise BundleError(f"{rel}: not strict JSON") from None
    if not _shape_ok(obj):
        raise BundleError(f"{rel}: nested too deeply or too large")
    return obj


def _zip_ok(data, rel, limit):
    """Stored members only, few of them, and no more bytes than the caller expects: checked
    before any decoder sees the archive, so a deflate bomb is never inflated."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            infos = z.infolist()
    except Exception:
        raise BundleError(f"{rel}: not a valid archive") from None
    if (len(infos) > MAX_ZIP_MEMBERS or any(i.compress_type != zipfile.ZIP_STORED for i in infos)
            or sum(i.file_size for i in infos) > limit):
        raise BundleError(f"{rel}: archive members not plain or too large")


def _load_head(data, head, input_dim):
    rel = f"heads/{head}.pth"
    model = ResNetMLP(input_dim, NUM_OUT[head])
    ref = model.state_dict()
    _zip_ok(data, rel, sum(v.numel() * v.element_size() for v in ref.values()) + ZIP_SLACK)
    try:
        sd = torch.load(io.BytesIO(data), map_location="cpu", weights_only=True)
    except Exception:
        raise BundleError(f"{rel}: not a plain state dict") from None
    if (not isinstance(sd, dict) or set(sd) != set(ref)
            or not all(isinstance(v, torch.Tensor) for v in sd.values())):
        raise BundleError(f"{rel}: keys do not match the head")
    for k, v in sd.items():
        if v.shape != ref[k].shape or v.dtype != ref[k].dtype or not bool(torch.isfinite(v).all()):
            raise BundleError(f"{rel}: tensor {k} does not match the head")
    try:
        model.load_state_dict(sd, strict=True)
    except Exception:
        raise BundleError(f"{rel}: state dict rejected") from None
    return model.eval()


def _load_knn(data, input_dim):
    rel = "knn_index.npz"
    _zip_ok(data, rel, MAX_FILE)
    try:
        with np.load(io.BytesIO(data), allow_pickle=False) as npz:
            if set(npz.files) != {"embeddings", "label_ids", "case_ids"}:
                raise BundleError(f"{rel}: wrong arrays")
            emb, lab, cid = npz["embeddings"], npz["label_ids"], npz["case_ids"]
    except BundleError:
        raise
    except Exception:
        raise BundleError(f"{rel}: not a plain npz") from None
    if emb.dtype != np.float32 or emb.ndim != 2 or emb.shape[1] != input_dim or not np.isfinite(emb).all():
        raise BundleError(f"{rel}: embeddings must be float32 of width input_dim")
    if lab.dtype != np.int64 or lab.shape != (len(emb),) or (len(lab) and (lab.min() < 0 or lab.max() > 2)):
        raise BundleError(f"{rel}: bad label_ids")
    if cid.dtype != np.int64 or cid.ndim != 1 or len(cid) not in (0, len(emb)):
        raise BundleError(f"{rel}: bad case_ids")
    return Knn(emb, lab, cid if len(cid) else None)


def read_bundle(dir, *, manifest_sha256: str) -> Bundle:
    """Ruling E14: manifest_sha256 (pinned by the caller, never read from the bundle) is compared
    to the manifest bytes before anything is parsed."""
    root = _open_dir(os.fspath(dir))
    try:
        top = set(os.listdir(root))
        raw, spent = _read_file(root, MANIFEST, MANIFEST, 0)
        if not (isinstance(manifest_sha256, str)
                and hmac.compare_digest(hashlib.sha256(raw).hexdigest(), manifest_sha256.lower())):
            raise BundleError(f"{MANIFEST}: hash does not match the pinned manifest hash")
        manifest = _parse_json(raw, MANIFEST)
        files = manifest.get("files") if isinstance(manifest, dict) else None
        if not isinstance(files, dict):
            raise BundleError(f"{MANIFEST}: files missing")
        for k, v in files.items():
            if k not in BUNDLE_FILES:
                raise BundleError(f"{MANIFEST}: unexpected entry {_name(k)}")
            if not isinstance(v, str) or len(v) != 64 or any(c not in "0123456789abcdef" for c in v):
                raise BundleError(f"{MANIFEST}: bad hash for {k}")
        if set(files) != set(BUNDLE_FILES):
            raise BundleError(f"{MANIFEST}: missing entry {sorted(set(BUNDLE_FILES) - set(files))[0]}")
        if top - _TOP:
            raise BundleError(f"unexpected file {_name(sorted(top - _TOP)[0])}")
        heads_fd = _open_dir("heads", root)
        try:
            extra = set(os.listdir(heads_fd)) - {f"{h}.pth" for h in HEADS}
            if extra:
                raise BundleError(f"unexpected file in heads: {_name(sorted(extra)[0])}")
            data = {}
            for rel in BUNDLE_FILES:
                if rel.startswith("heads/"):
                    data[rel], spent = _read_file(heads_fd, rel[6:], rel, spent)
                else:
                    data[rel], spent = _read_file(root, rel, rel, spent)
                if not hmac.compare_digest(hashlib.sha256(data[rel]).hexdigest(), files[rel]):
                    raise BundleError(f"{rel}: hash mismatch")
        finally:
            os.close(heads_fd)
    finally:
        os.close(root)

    # everything below parses the already verified bytes
    _check_manifest_fields(manifest)
    dim = manifest["input_dim"]
    models = {h: _load_head(data[f"heads/{h}.pth"], h, dim) for h in HEADS}
    calibration = _parse_json(data["calibration.json"], "calibration.json")
    _check_calibration(calibration)
    calibration["temperature"] = {k: float(v) for k, v in calibration["temperature"].items()}
    return Bundle(Heads(models, dim), calibration, _load_knn(data["knn_index.npz"], dim),
                  _parse_json(data["campaign_profile.json"], "campaign_profile.json"), manifest, dim)
