import hashlib
import json
import os
import re
import shutil
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
    b = read_bundle(bdir)
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
    p = bdir / "heads" / "safe.pth"
    raw = bytearray(p.read_bytes())
    raw[len(raw) // 2] ^= 1
    p.write_bytes(bytes(raw))
    with pytest.raises(BundleError, match="safe.pth"):
        read_bundle(bdir)


def test_missing_head(bdir):
    (bdir / "heads" / "safe.pth").unlink()
    with pytest.raises(BundleError, match="safe.pth"):
        read_bundle(bdir)


def test_extra_file(bdir):
    (bdir / "extra.txt").write_text("x")
    with pytest.raises(BundleError, match="extra.txt"):
        read_bundle(bdir)
    (bdir / "extra.txt").unlink()
    (bdir / "heads" / "evil.pth").write_bytes(b"x")
    with pytest.raises(BundleError, match="evil.pth"):
        read_bundle(bdir)


@pytest.mark.parametrize("name", ["../x.pth", "/etc/passwd", "heads/sub/a.pth", "heads\\a.pth"])
def test_bad_name_in_manifest(bdir, name):
    _rewrite_manifest(bdir, lambda m: m["files"].__setitem__(name, "0" * 64))
    with pytest.raises(BundleError):
        read_bundle(bdir)


def test_manifest_lists_file_not_on_disk(bdir):
    _rewrite_manifest(bdir, lambda m: m["files"].__setitem__("heads/ghost.pth", "0" * 64))
    with pytest.raises(BundleError, match="ghost.pth"):
        read_bundle(bdir)


def test_manifest_hash_mismatch(bdir):
    _rewrite_manifest(bdir, lambda m: m["files"].__setitem__("calibration.json", "0" * 64))
    with pytest.raises(BundleError, match="calibration.json"):
        read_bundle(bdir)


def test_symlink_refused(bdir, tmp_path):
    target = tmp_path / "real.json"
    shutil.copy(bdir / "campaign_profile.json", target)
    (bdir / "campaign_profile.json").unlink()
    (bdir / "campaign_profile.json").symlink_to(target)
    with pytest.raises(BundleError, match="campaign_profile.json"):
        read_bundle(bdir)


def test_symlinked_dir_refused(bdir, tmp_path):
    link = tmp_path / "link"
    link.symlink_to(bdir)
    with pytest.raises(BundleError):
        read_bundle(link)


def test_directory_instead_of_file(bdir):
    (bdir / "knn_index.npz").unlink()
    (bdir / "knn_index.npz").mkdir()
    with pytest.raises(BundleError, match="knn_index.npz"):
        read_bundle(bdir)


def test_knn_object_array_refused(bdir):
    np.savez(bdir / "knn_index.npz", embeddings=np.array([{"a": 1}], dtype=object),
             label_ids=np.array([0]), case_ids=np.array([1]))
    _rehash(bdir, "knn_index.npz")
    with pytest.raises(BundleError, match="knn_index.npz"):
        read_bundle(bdir)


def test_truncated_npz(bdir):
    p = bdir / "knn_index.npz"
    p.write_bytes(p.read_bytes()[:100])
    _rehash(bdir, "knn_index.npz")
    with pytest.raises(BundleError, match="knn_index.npz"):
        read_bundle(bdir)


def test_head_not_a_state_dict(bdir):
    torch.save({"fc1.weight": [1, 2]}, bdir / "heads" / "safe.pth")
    _rehash(bdir, "heads/safe.pth")
    with pytest.raises(BundleError, match="safe.pth"):
        read_bundle(bdir)


def test_head_wrong_shape(bdir):
    sd = ResNetMLP(DIM + 3, 2).state_dict()
    torch.save(sd, bdir / "heads" / "safe.pth")
    _rehash(bdir, "heads/safe.pth")
    with pytest.raises(BundleError, match="safe.pth"):
        read_bundle(bdir)


class _Evil:
    def __reduce__(self):
        return (Path(os.environ["MARKER"]).write_text, ("pwned",))


def test_pickle_in_pth_not_executed(bdir, tmp_path, monkeypatch):
    marker = tmp_path / "marker"
    monkeypatch.setenv("MARKER", str(marker))
    torch.save(_Evil(), bdir / "heads" / "safe.pth")
    _rehash(bdir, "heads/safe.pth")
    with pytest.raises(BundleError, match="safe.pth"):
        read_bundle(bdir)
    assert not marker.exists()


def test_torch_load_always_weights_only(bdir):
    real = torch.load
    calls = []

    def spy(*a, **k):
        calls.append(k)
        return real(*a, **k)

    with mock.patch.object(torch, "load", spy):
        read_bundle(bdir)
    assert len(calls) == len(HEADS) and all(c.get("weights_only") is True for c in calls)


def test_torch_load_only_in_bundle():
    root = Path(bundle_mod.__file__).parent
    users = [p.name for p in root.glob("*.py") if re.search(r"torch\.load\(", p.read_text())]
    assert users == ["bundle.py"]


def test_size_cap_total(bdir):
    with mock.patch.object(bundle_mod, "MAX_TOTAL", 1000):
        with pytest.raises(BundleError, match="size"):
            read_bundle(bdir)


def test_size_cap_single_file(bdir):
    with mock.patch.object(bundle_mod, "MAX_FILE", 100):
        with pytest.raises(BundleError, match="size"):
            read_bundle(bdir)


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
        read_bundle(bdir)


def test_bad_cutoff_on_read(bdir):
    cal = json.loads((bdir / "calibration.json").read_text())
    cal["tier_cutoffs"]["high"] = 1.5
    (bdir / "calibration.json").write_text(json.dumps(cal))
    _rehash(bdir, "calibration.json")
    with pytest.raises(BundleError, match="calibration.json"):
        read_bundle(bdir)


def test_write_refuses_bad_temperature(tmp_path):
    heads, cal, knn, prof, man = _parts()
    cal["temperature"]["knn"] = float("inf")
    with pytest.raises(BundleError):
        write_bundle(tmp_path / "b", heads=heads, calibration=cal, knn=knn,
                     campaign_profile=prof, manifest=man)


def test_input_dim_mismatch(bdir):
    _rewrite_manifest(bdir, lambda m: m.__setitem__("input_dim", DIM + 1))
    with pytest.raises(BundleError):
        read_bundle(bdir)


def test_knn_width_mismatch(bdir):
    np.savez(bdir / "knn_index.npz", embeddings=np.zeros((3, DIM + 1), np.float32),
             label_ids=np.array([0, 1, 2]), case_ids=np.array([1, 2, 3]))
    _rehash(bdir, "knn_index.npz")
    with pytest.raises(BundleError, match="knn_index.npz"):
        read_bundle(bdir)


def test_json_depth_refused(bdir):
    (bdir / "campaign_profile.json").write_text("[" * 5000 + "]" * 5000)
    _rehash(bdir, "campaign_profile.json")
    with pytest.raises(BundleError, match="campaign_profile.json"):
        read_bundle(bdir)


def test_manifest_missing_field(bdir):
    _rewrite_manifest(bdir, lambda m: m.pop("recipe_id"))
    with pytest.raises(BundleError, match="recipe_id"):
        read_bundle(bdir)
