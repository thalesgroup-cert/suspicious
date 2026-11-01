import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import textwrap
import zipfile
from pathlib import Path
from unittest import mock

import numpy as np
import pytest
import torch

from ResNetMLP import ResNetMLP
from training import bundle as bundle_mod
from training.bundle import BUNDLE_FILES, BundleError, read_bundle, write_bundle
from training.recipe import HEADS, NUM_OUT, PREPROCESSING_VERSION_TOKENS, Heads, Knn

DIM = 12


def _heads():
    torch.manual_seed(0)
    return Heads({h: ResNetMLP(DIM, NUM_OUT[h]).eval() for h in HEADS}, DIM)


def _parts():
    rng = np.random.default_rng(0)
    knn = Knn(rng.normal(size=(9, DIM)).astype(np.float32), np.array([0, 1, 2] * 3),
              np.arange(100, 109))
    calibration = {"temperature": {"hierarchy": 1.5, "knn": 0.8},
                   "tier_cutoffs": {"high": 0.9, "medium": 0.6}, "held_out_groups": [1, 2, 3]}
    manifest = {"version_id": "v1", "recipe_id": "r1", "preprocessing_version": PREPROCESSING_VERSION_TOKENS,
                "encoder_id": "enc", "encoder_hash": "ab" * 8, "ledger_digest": "cd" * 8,
                "campaign_refs_digest": "ef" * 8, "metrics": {"acc": 0.85}, "gate": {"eligible": True},
                "parent_version": None, "trainer_revision": "abc123"}
    return _heads(), calibration, knn, {"centroids": [[0.1, 0.2]]}, manifest


def rb(d, **kw):
    """read_bundle pinned to the manifest currently on disk (tests that tamper re-pin)."""
    h = hashlib.sha256((Path(d) / "manifest.json").read_bytes()).hexdigest()
    return read_bundle(d, manifest_sha256=kw.pop("sha", h), **kw)


@pytest.fixture
def bdir(tmp_path):
    heads, cal, knn, prof, man = _parts()
    d = tmp_path / "b"
    write_bundle(d, heads=heads, calibration=cal, knn=knn, campaign_profile=prof, manifest=man)
    return d


def _rewrite_manifest(d, mutate):
    m = json.loads((d / "manifest.json").read_text())
    mutate(m)
    (d / "manifest.json").write_text(json.dumps(m))


def _rehash(d, rel):
    _rewrite_manifest(d, lambda m: m["files"].__setitem__(
        rel, hashlib.sha256((d / rel).read_bytes()).hexdigest()))


def test_round_trip(bdir):
    heads, cal, knn, prof, man = _parts()
    b = rb(bdir)
    assert b.input_dim == DIM and b.heads.input_dim == DIM
    for h in HEADS:
        a, c = heads.models[h].state_dict(), b.heads.models[h].state_dict()
        assert a.keys() == c.keys() and all(torch.equal(a[k], c[k]) for k in a)
        assert not b.heads.models[h].training
    assert b.calibration == cal and b.campaign_profile == prof
    assert np.array_equal(b.knn.embeddings, knn.embeddings)
    assert np.array_equal(b.knn.labels, knn.labels) and np.array_equal(b.knn.case_ids, knn.case_ids)
    assert b.manifest["version_id"] == "v1" and b.manifest["input_dim"] == DIM


def test_manifest_lists_hash_of_every_other_file(bdir):
    files = json.loads((bdir / "manifest.json").read_text())["files"]
    assert set(files) == set(BUNDLE_FILES) and "manifest.json" not in files
    for rel, h in files.items():
        assert hashlib.sha256((bdir / rel).read_bytes()).hexdigest() == h
    on_disk = {p.relative_to(bdir).as_posix() for p in bdir.rglob("*") if p.is_file()}
    assert on_disk == set(BUNDLE_FILES) | {"manifest.json"}


def test_write_is_atomic_and_leaves_no_temp(tmp_path):
    heads, cal, knn, prof, man = _parts()
    with mock.patch.object(bundle_mod, "_check_calibration", side_effect=BundleError("x")):
        with pytest.raises(BundleError):
            write_bundle(tmp_path / "b", heads=heads, calibration=cal, knn=knn,
                         campaign_profile=prof, manifest=man)
    assert list(tmp_path.iterdir()) == []


def test_flipped_byte_in_head(bdir):
    p = bdir / "heads" / "safe.npz"
    raw = bytearray(p.read_bytes())
    raw[len(raw) // 2] ^= 1
    p.write_bytes(bytes(raw))
    with pytest.raises(BundleError, match="safe.npz"):
        rb(bdir)


def test_missing_head(bdir):
    (bdir / "heads" / "safe.npz").unlink()
    with pytest.raises(BundleError, match="safe.npz"):
        rb(bdir)


def test_extra_file(bdir):
    (bdir / "extra.txt").write_text("x")
    with pytest.raises(BundleError, match="extra.txt"):
        rb(bdir)
    (bdir / "extra.txt").unlink()
    (bdir / "heads" / "evil.npz").write_bytes(b"x")
    with pytest.raises(BundleError, match="evil.npz"):
        rb(bdir)


@pytest.mark.parametrize("name", ["../x.npz", "/etc/passwd", "heads/sub/a.npz", "heads\\a.npz"])
def test_bad_name_in_manifest(bdir, name):
    _rewrite_manifest(bdir, lambda m: m["files"].__setitem__(name, "0" * 64))
    with pytest.raises(BundleError):
        rb(bdir)


def test_manifest_lists_file_not_on_disk(bdir):
    _rewrite_manifest(bdir, lambda m: m["files"].__setitem__("heads/ghost.npz", "0" * 64))
    with pytest.raises(BundleError, match="ghost.npz"):
        rb(bdir)


def test_manifest_hash_mismatch(bdir):
    _rewrite_manifest(bdir, lambda m: m["files"].__setitem__("calibration.json", "0" * 64))
    with pytest.raises(BundleError, match="calibration.json"):
        rb(bdir)


def test_symlink_refused(bdir, tmp_path):
    target = tmp_path / "real.json"
    shutil.copy(bdir / "campaign_profile.json", target)
    (bdir / "campaign_profile.json").unlink()
    (bdir / "campaign_profile.json").symlink_to(target)
    with pytest.raises(BundleError, match="campaign_profile.json"):
        rb(bdir)


def test_symlinked_dir_refused(bdir, tmp_path):
    link = tmp_path / "link"
    link.symlink_to(bdir)
    with pytest.raises(BundleError):
        rb(link)


def test_directory_instead_of_file(bdir):
    (bdir / "knn_index.npz").unlink()
    (bdir / "knn_index.npz").mkdir()
    with pytest.raises(BundleError, match="knn_index.npz"):
        rb(bdir)


def test_knn_object_array_refused(bdir):
    np.savez(bdir / "knn_index.npz", embeddings=np.array([{"a": 1}], dtype=object),
             label_ids=np.array([0]), case_ids=np.array([1]))
    _rehash(bdir, "knn_index.npz")
    with pytest.raises(BundleError, match="knn_index.npz"):
        rb(bdir)


def test_truncated_npz(bdir):
    p = bdir / "knn_index.npz"
    p.write_bytes(p.read_bytes()[:100])
    _rehash(bdir, "knn_index.npz")
    with pytest.raises(BundleError, match="knn_index.npz"):
        rb(bdir)


class _Evil:
    def __reduce__(self):
        return (Path(os.environ["MARKER"]).write_text, ("pwned",))


def test_size_cap_total(bdir):
    with mock.patch.object(bundle_mod, "MAX_TOTAL", 1000):
        with pytest.raises(BundleError, match="size"):
            rb(bdir)


def test_size_cap_single_file(bdir):
    with mock.patch.object(bundle_mod, "MAX_FILE", 100):
        with pytest.raises(BundleError, match="size"):
            rb(bdir)


def test_default_caps():
    assert bundle_mod.MAX_TOTAL == 100 * 2**20 and bundle_mod.MAX_FILE == 50 * 2**20


@pytest.mark.parametrize("temp", [{"hierarchy": float("nan"), "knn": 1.0},
                                  {"hierarchy": 0.0, "knn": 1.0}, {"hierarchy": 1.0},
                                  {"hierarchy": True, "knn": 1.0}, 1.0])
def test_bad_temperature_on_read(bdir, temp):
    cal = json.loads((bdir / "calibration.json").read_text())
    cal["temperature"] = temp
    (bdir / "calibration.json").write_text(json.dumps(cal))  # NaN written as the bare token
    _rehash(bdir, "calibration.json")
    with pytest.raises(BundleError, match="calibration.json"):
        rb(bdir)


def test_bad_cutoff_on_read(bdir):
    cal = json.loads((bdir / "calibration.json").read_text())
    cal["tier_cutoffs"]["high"] = 1.5
    (bdir / "calibration.json").write_text(json.dumps(cal))
    _rehash(bdir, "calibration.json")
    with pytest.raises(BundleError, match="calibration.json"):
        rb(bdir)


def test_write_refuses_bad_temperature(tmp_path):
    heads, cal, knn, prof, man = _parts()
    cal["temperature"]["knn"] = float("inf")
    with pytest.raises(BundleError):
        write_bundle(tmp_path / "b", heads=heads, calibration=cal, knn=knn,
                     campaign_profile=prof, manifest=man)


def test_input_dim_mismatch(bdir):
    _rewrite_manifest(bdir, lambda m: m.__setitem__("input_dim", DIM + 1))
    with pytest.raises(BundleError):
        rb(bdir)


def test_knn_width_mismatch(bdir):
    np.savez(bdir / "knn_index.npz", embeddings=np.zeros((3, DIM + 1), np.float32),
             label_ids=np.array([0, 1, 2]), case_ids=np.array([1, 2, 3]))
    _rehash(bdir, "knn_index.npz")
    with pytest.raises(BundleError, match="knn_index.npz"):
        rb(bdir)


def test_json_depth_refused(bdir):
    (bdir / "campaign_profile.json").write_text("[" * 5000 + "]" * 5000)
    _rehash(bdir, "campaign_profile.json")
    with pytest.raises(BundleError, match="campaign_profile.json"):
        rb(bdir)


def test_manifest_missing_field(bdir):
    _rewrite_manifest(bdir, lambda m: m.pop("recipe_id"))
    with pytest.raises(BundleError, match="recipe_id"):
        rb(bdir)


# --- fix wave ------------------------------------------------------------------------------------


def _rewrite_zip(path, compress, extra=None):
    with zipfile.ZipFile(path) as z:
        items = [(i.filename, z.read(i)) for i in z.infolist()]
    with zipfile.ZipFile(path, "w", compress) as z:
        for n, d in items:
            z.writestr(n, d, compress_type=compress)
        if extra:
            z.writestr(extra[0], extra[1], compress_type=compress)


def test_deflated_head_member_refused_before_load(bdir):
    p = bdir / "heads" / "safe_suspicious.npz"
    _rewrite_zip(p, zipfile.ZIP_DEFLATED)
    _rehash(bdir, "heads/safe_suspicious.npz")
    with mock.patch.object(torch, "load") as load:
        with pytest.raises(BundleError, match="safe_suspicious.npz"):
            rb(bdir)
    load.assert_not_called()


def test_oversized_stored_head_member_refused(bdir):
    p = bdir / "heads" / "safe.npz"
    _rewrite_zip(p, zipfile.ZIP_STORED, ("archive/extra", bytes(300_000)))
    _rehash(bdir, "heads/safe.npz")
    with pytest.raises(BundleError, match="safe.npz"):
        rb(bdir)


def test_deflated_npz_refused(bdir):
    np.savez_compressed(bdir / "knn_index.npz", embeddings=np.zeros((50000, DIM), np.float32),
                        label_ids=np.zeros(50000, np.int64), case_ids=np.zeros(50000, np.int64))
    _rehash(bdir, "knn_index.npz")
    with pytest.raises(BundleError, match="knn_index.npz"):
        rb(bdir)


@pytest.mark.parametrize("rel,cap", [("manifest.json", 512 * 1024), ("calibration.json", 64 * 1024),
                                     ("campaign_profile.json", 256 * 1024)])
def test_json_caps(bdir, rel, cap):
    assert bundle_mod.JSON_CAPS[rel] == cap
    pad = " " * (cap + 1)
    if rel == "manifest.json":
        (bdir / rel).write_text(json.dumps({}) + pad)
    else:
        (bdir / rel).write_text("{}" + pad)
        _rehash(bdir, rel)
    with pytest.raises(BundleError, match="size"):
        rb(bdir)


def test_json_node_count(bdir):
    (bdir / "campaign_profile.json").write_text("[" + "{}," * 80000 + "{}]")
    _rehash(bdir, "campaign_profile.json")
    with pytest.raises(BundleError, match="campaign_profile.json"):
        rb(bdir)


def test_json_duplicate_keys(bdir):
    (bdir / "campaign_profile.json").write_text('{"a": 1, "a": 2}')
    _rehash(bdir, "campaign_profile.json")
    with pytest.raises(BundleError, match="campaign_profile.json"):
        rb(bdir)


@pytest.mark.parametrize("where", ["manifest", "campaign_profile", "gate"])
def test_json_overflow_float(bdir, where):
    if where == "campaign_profile":
        (bdir / "campaign_profile.json").write_text('{"x": 1e999}')
        _rehash(bdir, "campaign_profile.json")
    else:
        raw = (bdir / "manifest.json").read_text()
        key = '"gate": {"eligible": true}'
        raw = raw.replace(key, '"gate": {"x": 1e999}') if where == "gate" else raw[:-1] + ', "x": 1e999}'
        assert "1e999" in raw
        (bdir / "manifest.json").write_text(raw)
    with pytest.raises(BundleError):
        rb(bdir)


def test_pin_right_and_wrong(bdir):
    good = hashlib.sha256((bdir / "manifest.json").read_bytes()).hexdigest()
    assert read_bundle(bdir, manifest_sha256=good).input_dim == DIM
    with pytest.raises(BundleError, match="manifest"):
        read_bundle(bdir, manifest_sha256="0" * 64)
    with pytest.raises(TypeError):
        read_bundle(bdir)


def test_pin_checked_before_parse(bdir):
    good = hashlib.sha256((bdir / "manifest.json").read_bytes()).hexdigest()
    (bdir / "manifest.json").write_text("{not json")
    with pytest.raises(BundleError, match="hash"):
        read_bundle(bdir, manifest_sha256=good)


def test_consistent_but_different_manifest_refused(bdir):
    good = hashlib.sha256((bdir / "manifest.json").read_bytes()).hexdigest()
    _rewrite_manifest(bdir, lambda m: m.__setitem__("version_id", "evil"))
    assert rb(bdir).manifest["version_id"] == "evil"  # self-consistent
    with pytest.raises(BundleError, match="hash"):
        read_bundle(bdir, manifest_sha256=good)


def test_write_returns_manifest_hash(tmp_path):
    heads, cal, knn, prof, man = _parts()
    h = write_bundle(tmp_path / "b", heads=heads, calibration=cal, knn=knn, campaign_profile=prof,
                     manifest=man)
    assert h == hashlib.sha256((tmp_path / "b" / "manifest.json").read_bytes()).hexdigest()


def test_hard_link_refused(bdir, tmp_path):
    os.link(bdir / "campaign_profile.json", tmp_path / "other")
    with pytest.raises(BundleError, match="campaign_profile.json"):
        rb(bdir)


def test_heads_symlink_refused(bdir, tmp_path):
    shutil.move(bdir / "heads", tmp_path / "realheads")
    (bdir / "heads").symlink_to(tmp_path / "realheads")
    with pytest.raises(BundleError):
        rb(bdir)


@pytest.mark.parametrize("temp", [{"hierarchy": 31.0, "knn": 1.0}, {"hierarchy": 0.1, "knn": 1.0}])
def test_temperature_range(bdir, temp):
    cal = json.loads((bdir / "calibration.json").read_text())
    cal["temperature"] = temp
    (bdir / "calibration.json").write_text(json.dumps(cal))
    _rehash(bdir, "calibration.json")
    with pytest.raises(BundleError, match="calibration.json"):
        rb(bdir)


@pytest.mark.parametrize("cut", [{"high": 0.9}, {"high": 0.9, "medium": 0.6, "x": 0.1},
                                 {"high": 0.5, "medium": 0.6}, {"high": 0.9, "medium": -0.1}])
def test_tier_cutoff_shape(bdir, cut):
    cal = json.loads((bdir / "calibration.json").read_text())
    cal["tier_cutoffs"] = cut
    (bdir / "calibration.json").write_text(json.dumps(cal))
    _rehash(bdir, "calibration.json")
    with pytest.raises(BundleError, match="calibration.json"):
        rb(bdir)


def test_tier_keys_are_the_gates():
    from training import gate
    assert set(bundle_mod.TIER_CUTOFF_KEYS) == {"high", "medium"} == set(gate.TIER_CUTOFF_KEYS)


def test_knn_dtypes_strict(bdir):
    np.savez(bdir / "knn_index.npz", embeddings=np.zeros((3, DIM), np.float64),
             label_ids=np.array([0, 1, 2]), case_ids=np.array([1, 2, 3]))
    _rehash(bdir, "knn_index.npz")
    with pytest.raises(BundleError, match="knn_index.npz"):
        rb(bdir)
    np.savez(bdir / "knn_index.npz", embeddings=np.zeros((3, DIM), np.float32),
             label_ids=np.array([0, 1, 2]), case_ids=np.array(["a", "b", "c"]))
    _rehash(bdir, "knn_index.npz")
    with pytest.raises(BundleError, match="knn_index.npz"):
        rb(bdir)


def test_write_rename_collision_is_bundle_error(tmp_path):
    heads, cal, knn, prof, man = _parts()
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / "f").write_text("x")
    with pytest.raises(BundleError):
        write_bundle(tmp_path / "b", heads=heads, calibration=cal, knn=knn, campaign_profile=prof,
                     manifest=man)
    assert [p.name for p in tmp_path.iterdir()] == ["b"]


def test_write_fsyncs(tmp_path):
    heads, cal, knn, prof, man = _parts()
    with mock.patch.object(os, "fsync") as fs:
        write_bundle(tmp_path / "b", heads=heads, calibration=cal, knn=knn, campaign_profile=prof,
                     manifest=man)
    assert fs.call_count >= 9 + 3


# --- fix wave 2 (Ruling E15: heads are npz, torch.load is gone from the bundle) ------------------

def _save(path, sd):
    np.savez(path, **{k: v.detach().numpy() if hasattr(v, "detach") else v for k, v in sd.items()})


def _sd(dim=DIM, out=2):
    return {k: v.clone() for k, v in ResNetMLP(dim, out).state_dict().items()}


def _bad_head(bdir, sd):
    _save(bdir / "heads" / "safe.npz", sd)
    _rehash(bdir, "heads/safe.npz")
    with pytest.raises(BundleError, match="safe.npz"):
        rb(bdir)


def test_head_float64_refused(bdir):
    _bad_head(bdir, {k: v.numpy().astype(np.float64) for k, v in _sd().items()})


def test_head_float16_refused(bdir):
    _bad_head(bdir, {k: v.numpy().astype(np.float16) for k, v in _sd().items()})


def test_head_missing_key_refused(bdir):
    sd = _sd()
    sd.pop("fc1.bias")
    _bad_head(bdir, sd)


def test_head_extra_key_refused(bdir):
    sd = _sd()
    sd["extra"] = torch.zeros(2)
    _bad_head(bdir, sd)


def test_head_wrong_shape_refused(bdir):
    _bad_head(bdir, _sd(DIM + 3))


def test_head_nan_refused(bdir):
    sd = _sd()
    sd["fc1.weight"][0, 0] = float("nan")
    _bad_head(bdir, sd)


def test_head_object_array_not_executed(bdir, tmp_path, monkeypatch):
    marker = tmp_path / "marker"
    monkeypatch.setenv("MARKER", str(marker))
    sd = _sd()
    sd["fc1.bias"] = np.array([_Evil()], dtype=object)
    _bad_head(bdir, sd)
    assert not marker.exists()


class _Evil:
    def __reduce__(self):
        return (Path(os.environ["MARKER"]).write_text, ("pwned",))


def test_torch_load_not_called_and_not_in_source(bdir):
    with mock.patch.object(torch, "load", side_effect=AssertionError("torch.load called")):
        rb(bdir)
    assert "torch.load" not in Path(bundle_mod.__file__).read_text()
    root = Path(bundle_mod.__file__).parent
    assert not [p.name for p in root.glob("*.py") if "torch.load(" in p.read_text()]


_PROBE = textwrap.dedent("""
    import resource, sys
    sys.path.insert(0, %r)
    from training.bundle import read_bundle, BundleError
    try:
        read_bundle(sys.argv[1], manifest_sha256=sys.argv[2])
        r = "ok"
    except BundleError:
        r = "refused"
    print(r, resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
""") % str(Path(bundle_mod.__file__).parent.parent)


def _probe(d):
    h = hashlib.sha256((d / "manifest.json").read_bytes()).hexdigest()
    out = subprocess.run([sys.executable, "-I", "-c", _PROBE, str(d), h], capture_output=True,
                         text=True, timeout=120, check=True).stdout.split()
    return out[0], int(out[1]) // 1024  # MB


def _bomb_zip(path, name="fc1.weight.npy", mb=400):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z, z.open(name, "w", force_zip64=True) as f:
        chunk = bytes(1 << 20)
        for _ in range(mb):
            f.write(chunk)


def test_deflate_bomb_head_small_rss(bdir):
    base = _probe(bdir)
    assert base[0] == "ok"
    _bomb_zip(bdir / "heads" / "safe.npz")
    assert (bdir / "heads" / "safe.npz").stat().st_size < 3 * 2**20
    _rehash(bdir, "heads/safe.npz")
    res, mb = _probe(bdir)
    assert res == "refused" and mb - base[1] < 100


def test_fake_central_directory_before_end_record(bdir):
    """The reviewer's differential: a bomb zip (and a forged directory) in front of the real
    archive. Python's reader sees only the real one; either way nothing inflates."""
    p = bdir / "heads" / "safe.npz"
    legit = p.read_bytes()
    _bomb_zip(bdir / "bomb.tmp")
    bomb = (bdir / "bomb.tmp").read_bytes()
    (bdir / "bomb.tmp").unlink()
    i = bomb.rindex(b"PK\x01\x02")
    forged = bomb[i:]  # central directory + end record of the bomb
    p.write_bytes(bomb[:i] + forged[:-22] + legit)
    _rehash(bdir, "heads/safe.npz")
    base = _probe(bdir)
    res, mb = _probe(bdir)
    assert res in ("ok", "refused") and mb - base[1] < 100


def test_fifo_refused_without_blocking(bdir):
    (bdir / "campaign_profile.json").unlink()
    os.mkfifo(bdir / "campaign_profile.json")

    def boom(*_):
        raise TimeoutError("read_bundle blocked on a FIFO")

    old = signal.signal(signal.SIGALRM, boom)
    signal.alarm(5)
    try:
        with pytest.raises(BundleError, match="campaign_profile.json"):
            rb(bdir)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)


def test_running_total_with_growing_files(bdir):
    """Each file is under its own cap but the sum passes MAX_TOTAL: refused while reading."""
    sizes = [(bdir / "heads" / f"{h}.npz").stat().st_size for h in HEADS]
    limit = sum(sizes[:2]) + 10  # passes inside the third head
    with mock.patch.object(bundle_mod, "MAX_TOTAL", limit + (bdir / "manifest.json").stat().st_size):
        with pytest.raises(BundleError, match="total"):
            rb(bdir)
    with mock.patch.object(bundle_mod, "MAX_TOTAL", 10**9):
        rb(bdir)


def test_label_ids_must_be_int64(bdir):
    np.savez(bdir / "knn_index.npz", embeddings=np.zeros((3, DIM), np.float32),
             label_ids=np.array([0, 1, 2], np.int32), case_ids=np.array([1, 2, 3], np.int64))
    _rehash(bdir, "knn_index.npz")
    with pytest.raises(BundleError, match="label_ids"):
        rb(bdir)


@pytest.mark.parametrize("name", ["evil\nname", "x" * 61, "a b"])
def test_attacker_names_not_echoed(bdir, name):
    (bdir / name).write_text("x")
    with pytest.raises(BundleError) as e:
        rb(bdir)
    assert name not in str(e.value) and "\n" not in str(e.value)


def test_manifest_key_not_echoed(bdir):
    _rewrite_manifest(bdir, lambda m: m["files"].__setitem__("k" * 61, "0" * 64))
    with pytest.raises(BundleError) as e:
        rb(bdir)
    assert "k" * 61 not in str(e.value)


def test_plain_names_are_shown(bdir):
    (bdir / "extra.txt").write_text("x")
    with pytest.raises(BundleError, match="extra.txt"):
        rb(bdir)


def test_caller_path_shown_in_messages(tmp_path):
    with pytest.raises(BundleError) as e:
        read_bundle(tmp_path / "no such dir\twith odd", manifest_sha256="0" * 64)
    assert "no such dir" in str(e.value)


@pytest.mark.parametrize("v", [10**401, -(10**401), 2**53, float("inf")])
def test_huge_numbers_are_bundle_errors(bdir, v):
    cal = json.loads((bdir / "calibration.json").read_text())
    cal["temperature"]["knn"] = v if v != float("inf") else 1.0
    if v == float("inf"):
        cal["tier_cutoffs"]["high"] = v
    (bdir / "calibration.json").write_text(json.dumps(cal))
    _rehash(bdir, "calibration.json")
    with pytest.raises(BundleError, match="calibration.json"):
        rb(bdir)


@pytest.mark.parametrize("where", ["temperature", "tier_cutoffs"])
def test_huge_int_on_write(tmp_path, where):
    heads, cal, knn, prof, man = _parts()
    if where == "temperature":
        cal["temperature"]["knn"] = 10**401
    else:
        cal["tier_cutoffs"]["high"] = 10**401
    with pytest.raises(BundleError):
        write_bundle(tmp_path / "b", heads=heads, calibration=cal, knn=knn, campaign_profile=prof,
                     manifest=man)


def test_huge_int_read_from_json_text(bdir):
    (bdir / "calibration.json").write_text(
        '{"temperature": {"hierarchy": 1, "knn": %s}, "tier_cutoffs": {"high": 0.9, "medium": 0.6},'
        ' "held_out_groups": []}' % ("9" * 401))
    _rehash(bdir, "calibration.json")
    with pytest.raises(BundleError, match="calibration.json"):
        rb(bdir)


@pytest.mark.parametrize("pin", ["A" * 64, "0" * 63, "0" * 65, "é" * 64, "", ("0" * 64) + "\n", None])
def test_pin_must_be_lowercase_hex(bdir, pin):
    with pytest.raises(BundleError, match="pin"):
        read_bundle(bdir, manifest_sha256=pin)


def test_uppercase_correct_hash_refused(bdir):
    good = hashlib.sha256((bdir / "manifest.json").read_bytes()).hexdigest()
    with pytest.raises(BundleError, match="pin"):
        read_bundle(bdir, manifest_sha256=good.upper())


def test_missing_parent_is_bundle_error(tmp_path):
    heads, cal, knn, prof, man = _parts()
    with pytest.raises(BundleError):
        write_bundle(tmp_path / "nope" / "b", heads=heads, calibration=cal, knn=knn,
                     campaign_profile=prof, manifest=man)


def test_temperature_range_is_recipe_bounds():
    from training import recipe
    assert bundle_mod.TEMPERATURE_RANGE == tuple(float(x) for x in recipe.T_BOUNDS)
