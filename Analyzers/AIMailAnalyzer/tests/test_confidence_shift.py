"""Spec Risks, engine sensitivity: tools/confidence_shift.py prints the confidence_ai distribution
before (version 0's recipe, uncalibrated) and after (the retrain recipe, calibrated). The test pins
that the script runs and what it prints; it asserts no value."""
import numpy as np

from tests.test_training_gate import _data
from tools.confidence_shift import main


def test_prints_the_confidence_ai_distribution_before_and_after(tmp_path, capsys):
    X, folders, _, _ = _data(n_per=12)
    path = tmp_path / "d.npz"
    np.savez(path, embeddings=X, embeddings_tokens=X + 0.01, folders=folders)
    main(["--dataset", str(path), "--seeds", "0"])
    out = capsys.readouterr().out
    for line in ("before", "after"):
        assert f"{line} confidence_ai" in out and f"{line} classes" in out
    assert "Inconclusive" in out
