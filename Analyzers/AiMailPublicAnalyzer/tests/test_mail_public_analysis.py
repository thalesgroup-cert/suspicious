"""Torch-free tests: cascade thresholds and safe tar extraction."""
import io
import sys
import tarfile
import tempfile
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import mail_public_analysis as m  # noqa: E402


def test_info_levels():
    assert m.get_classification_info(np.array([0.9, 0.05, 0.05])) == {
        "classification": "SAFE", "confidence": 0.9, "level": "safe"}
    assert m.get_classification_info(np.array([0.1, 0.2, 0.7]))["level"] == "malicious"
    assert m.get_classification_info(np.array([0.1, 0.6, 0.3]))["level"] == "suspicious"


def test_low_confidence_is_inconclusive():
    info = m.get_classification_info(np.array([0.4, 0.35, 0.25]))
    assert info["classification"] == "INCONCLUSIVE" and info["level"] == "info"


def test_breakdown_is_labelled():
    assert m.get_classification_breakdown(np.array([0.5, 0.3, 0.2])) == {
        "SAFE": 0.5, "SUSPICIOUS": 0.3, "DANGEROUS": 0.2}


def _tar(path, name, data=b"x"):
    with tarfile.open(path, "w:gz") as t:
        info = tarfile.TarInfo(name)
        info.size = len(data)
        t.addfile(info, io.BytesIO(data))


def test_untar_ok_and_traversal_rejected():
    with tempfile.TemporaryDirectory() as d:
        good, bad = f"{d}/g.tgz", f"{d}/b.tgz"
        _tar(good, "mail.txt")
        _tar(bad, "../evil.txt")
        assert m.untar_file(good, f"{d}/out") is True
        assert (Path(d) / "out" / "mail.txt").exists()
        assert m.untar_file(bad, f"{d}/out2") is False
        assert not (Path(d) / "evil.txt").exists()
