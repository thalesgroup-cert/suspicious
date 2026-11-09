"""The model bundle (spec section 3): five heads, calibration, kNN index, campaign profile and a
manifest holding a SHA-256 per file. The bytes come from object storage through a presigned URL,
so they are untrusted: read_bundle reads every file once into memory, verifies all hashes, and only
then parses the same bytes (no TOCTOU). Heads are npz files (Ruling E15: no pickle and no
torch deserialiser on bundle bytes, because torch's zip reader and Python's disagree on archive layout):
float32 arrays that must match a freshly built ResNetMLP key for key and shape. Errors are a single BundleError naming the file or field, never
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
import struct
import tempfile
import zipfile
from dataclasses import dataclass

import numpy as np
import torch

from ResNetMLP import ResNetMLP
from training.gate import TIER_CUTOFF_KEYS
from training.recipe import HEADS, NUM_OUT, T_BOUNDS, Heads, Knn

MANIFEST = "manifest.json"
BUNDLE_FILES = (
    *(f"heads/{h}.npz" for h in HEADS),
    "calibration.json", "knn_index.npz", "campaign_profile.json",
)
MAX_TOTAL = 100 * 2**20
MAX_FILE = 50 * 2**20
JSON_CAPS = {MANIFEST: 512 * 1024, "calibration.json": 64 * 1024, "campaign_profile.json": 256 * 1024}
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 20000
MAX_ZIP_MEMBERS = 64
ZIP_SLACK = 64 * 1024
TEMPERATURE_RANGE = tuple(float(x) for x in T_BOUNDS)  # Ruling E12 fit bounds
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
    """Finite real; ints are bounded first so math.isfinite can never overflow."""
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return abs(v) < 2**53
    return isinstance(v, float) and math.isfinite(v)


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
    here. Returns the SHA-256 hex of manifest.json (Ruling E14: the caller pins it).
    Notes: an existing empty directory at the target is replaced, a non-empty path is refused, a
    missing parent raises BundleError, and the call may raise (OSError) after the bundle is in
    place if the final directory fsync fails."""
    dir = os.fspath(dir)
    _check_calibration(calibration)
    if set(heads.models) != set(HEADS):
        raise BundleError("heads: need exactly the five heads")
    manifest = {**manifest, "input_dim": heads.input_dim}
    _check_manifest_fields(manifest)

    blobs = {}
    for h in HEADS:
        buf = io.BytesIO()
        np.savez(buf, **{k: v.detach().cpu().numpy().astype(np.float32)
                         for k, v in heads.models[h].state_dict().items()})
        blobs[f"heads/{h}.npz"] = buf.getvalue()
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
    try:
        tmp = tempfile.mkdtemp(dir=parent, prefix=".bundle-")
    except FileNotFoundError:
        raise BundleError("bundle parent directory does not exist") from None
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
    """name is the caller's own path or the constant "heads": shown as is."""
    try:
        return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd)
    except OSError:
        raise BundleError(f"{name}: not a plain directory") from None


def _cap(rel):
    return min(MAX_FILE, JSON_CAPS.get(rel, MAX_FILE))


def read_file_capped(dir_fd, name, rel, spent):
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
        cap = min(_cap(rel), MAX_TOTAL - spent)
        if st.st_size > cap:
            raise BundleError(f"{rel}: size above the per-file cap" if st.st_size > _cap(rel)
                              else "bundle size above the total cap")
        parts, n = [], 0
        while True:  # one allocation of at most cap + 1 bytes per read, no list of chunks
            chunk = os.read(fd, min(cap, st.st_size) + 1 - n)
            if not chunk:
                break
            parts.append(chunk)
            n += len(chunk)
            if n > cap:
                raise BundleError(f"{rel}: size above the per-file cap" if n > _cap(rel)
                                  else "bundle size above the total cap")
        return (parts[0] if len(parts) == 1 else b"".join(parts)), spent + n
    finally:
        os.close(fd)


def json_shape_ok(v):
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
    if not json_shape_ok(obj):
        raise BundleError(f"{rel}: nested too deeply or too large")
    return obj


_EOCD = struct.Struct("<4s4H2LH")  # end of central directory record, no zip64, no comment
_LOCAL = struct.Struct("<26x2H")  # local file header: name and extra field lengths
MAX_CD_BYTES = 64 * 1024


def _zip_layout_ok(data, rel, max_len):
    """Parse the end record ourselves, before zipfile builds one ZipInfo per directory entry (a
    flood of empty entries would otherwise cost far more memory than the file). Accept only the
    layout np.savez writes: local headers from byte 0, the directory right after the last member,
    the end record last, no comment, no zip64. Returns (claimed entry count, directory offset)."""
    if len(data) > max_len:
        raise BundleError(f"{rel}: archive too large")
    if data[:4] != b"PK\x03\x04" or len(data) < _EOCD.size:
        raise BundleError(f"{rel}: archive does not start at a local header")
    sig, disk, cd_disk, n_disk, n_total, cd_size, cd_off, clen = _EOCD.unpack(data[-_EOCD.size:])
    # zipfile follows a zip64 locator right before the end record and then trusts the zip64
    # record's counts instead; np.savez never writes zip64 end records at these sizes
    zip64 = (data[-_EOCD.size - 20:-_EOCD.size - 16] == b"PK\x06\x07"
             or 0xFFFF in (n_disk, n_total) or 0xFFFFFFFF in (cd_size, cd_off))
    if sig != b"PK\x05\x06" or zip64 or disk or cd_disk or n_disk != n_total or clen:
        raise BundleError(f"{rel}: archive end record not accepted")
    if n_total > MAX_ZIP_MEMBERS:
        raise BundleError(f"{rel}: too many archive entries")
    if cd_size > MAX_CD_BYTES or cd_off + cd_size != len(data) - _EOCD.size:
        raise BundleError(f"{rel}: archive directory not accepted")
    return n_total, cd_off


def _members_contiguous(data, infos, cd_off):
    """Members back to back from byte 0 and the directory right after the last one: no gaps.
    Runs after every member was opened (zipfile checked each local header there)."""
    end = 0
    for i in sorted(infos, key=lambda i: i.header_offset):
        if i.header_offset != end:
            return False
        nlen, xlen = _LOCAL.unpack_from(data, end)  # z.open already checked each signature
        end += _LOCAL.size + nlen + xlen + i.compress_size
    return end == cd_off


def npz_shapes(data, rel, max_len):
    """Stored members only, laid out as np.savez writes them, and every array header exactly
    consistent with its member size, all checked before any array is read: a deflate bomb, a
    directory flood or a lying header is never inflated or allocated. Returns
    {array name: (shape, dtype)}."""
    n_total, cd_off = _zip_layout_ok(data, rel, max_len)
    out = {}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            infos = z.infolist()
            if len(infos) != n_total:
                raise BundleError(f"{rel}: archive entry count does not match the directory")
            if any(i.compress_type != zipfile.ZIP_STORED for i in infos):
                raise BundleError(f"{rel}: archive members not stored")
            for i in infos:
                name = i.filename[:-4]
                if not i.filename.endswith(".npy") or name in out:
                    raise BundleError(f"{rel}: unexpected archive member")
                with z.open(i) as f:
                    ver = np.lib.format.read_magic(f)
                    if ver not in ((1, 0), (2, 0)):
                        raise BundleError(f"{rel}: unsupported array format")
                    read = (np.lib.format.read_array_header_1_0 if ver == (1, 0)
                            else np.lib.format.read_array_header_2_0)
                    shape, _, dtype = read(f)
                    header_len = f.tell()
                if dtype.hasobject or any(d < 0 for d in shape):
                    raise BundleError(f"{rel}: array header not accepted")
                if header_len + math.prod(shape) * dtype.itemsize != i.file_size or i.file_size != i.compress_size:
                    raise BundleError(f"{rel}: array header does not fit the member")
                out[name] = (shape, dtype)
            if not _members_contiguous(data, infos, cd_off):
                raise BundleError(f"{rel}: archive members not contiguous")
    except BundleError:
        raise
    except Exception:
        raise BundleError(f"{rel}: not a valid archive") from None
    return out


def _load_head(data, head, input_dim):
    rel = f"heads/{head}.npz"
    model = ResNetMLP(input_dim, NUM_OUT[head])
    ref = model.state_dict()
    shapes = npz_shapes(data, rel, sum(v.numel() * 4 for v in ref.values()) + ZIP_SLACK)
    if set(shapes) != set(ref):
        raise BundleError(f"{rel}: keys do not match the head")
    for k, (shape, dtype) in shapes.items():
        if shape != tuple(ref[k].shape) or dtype != np.float32:
            raise BundleError(f"{rel}: array {k} does not match the head")
    try:
        with np.load(io.BytesIO(data), allow_pickle=False) as npz:
            sd = {k: torch.from_numpy(npz[k].copy()) for k in ref}
    except Exception:
        raise BundleError(f"{rel}: unreadable arrays") from None
    if not all(bool(torch.isfinite(v).all()) for v in sd.values()):
        raise BundleError(f"{rel}: non-finite values")
    try:
        model.load_state_dict(sd, strict=True)
    except Exception:
        raise BundleError(f"{rel}: state dict rejected") from None
    return model.eval()


def _load_knn(data, input_dim):
    rel = "knn_index.npz"
    if set(npz_shapes(data, rel, MAX_FILE)) != {"embeddings", "label_ids", "case_ids"}:
        raise BundleError(f"{rel}: wrong arrays")
    try:
        with np.load(io.BytesIO(data), allow_pickle=False) as npz:
            emb, lab, cid = npz["embeddings"], npz["label_ids"], npz["case_ids"]
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
    if not isinstance(manifest_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", manifest_sha256):
        raise BundleError("manifest pin must be 64 lowercase hex characters")
    pin = manifest_sha256.encode("ascii")
    root = _open_dir(os.fspath(dir))
    try:
        top = set(os.listdir(root))
        raw, spent = read_file_capped(root, MANIFEST, MANIFEST, 0)
        if not hmac.compare_digest(hashlib.sha256(raw).hexdigest().encode(), pin):
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
            extra = set(os.listdir(heads_fd)) - {f"{h}.npz" for h in HEADS}
            if extra:
                raise BundleError(f"unexpected file in heads: {_name(sorted(extra)[0])}")
            data = {}
            for rel in BUNDLE_FILES:
                if rel.startswith("heads/"):
                    data[rel], spent = read_file_capped(heads_fd, rel[6:], rel, spent)
                else:
                    data[rel], spent = read_file_capped(root, rel, rel, spent)
                if not hmac.compare_digest(hashlib.sha256(data[rel]).hexdigest(), files[rel]):
                    raise BundleError(f"{rel}: hash mismatch")
        finally:
            os.close(heads_fd)
    finally:
        os.close(root)

    # everything below parses the already verified bytes
    _check_manifest_fields(manifest)
    dim = manifest["input_dim"]
    models = {h: _load_head(data[f"heads/{h}.npz"], h, dim) for h in HEADS}
    calibration = _parse_json(data["calibration.json"], "calibration.json")
    _check_calibration(calibration)
    calibration["temperature"] = {k: float(v) for k, v in calibration["temperature"].items()}
    return Bundle(Heads(models, dim), calibration, _load_knn(data["knn_index.npz"], dim),
                  _parse_json(data["campaign_profile.json"], "campaign_profile.json"), manifest, dim)
