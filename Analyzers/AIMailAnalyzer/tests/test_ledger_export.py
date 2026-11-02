"""Django's ledger export (Suspicious/Suspicious/ai_model/training_data.py, which export_ledger()
uses to write the file) against the training package: the copied constants match, and the file it
builds reads back through the real training/dataset.py reader. training_data.py has no Django, so
it is loaded here by path."""
import importlib.util
from pathlib import Path

import numpy as np
import pytest

pytest.importorskip("torch")

from training import dataset, gate, recipe  # noqa: E402

AI_MODEL = Path(__file__).resolve().parents[3] / "Suspicious/Suspicious/ai_model"
pytestmark = pytest.mark.skipif(not AI_MODEL.exists(), reason="Django tree not next to the analyzer")


def load(name):
    spec = importlib.util.spec_from_file_location(f"django_{name}", AI_MODEL / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def td():
    return load("training_data")


def test_copied_constants_match_the_training_package(td):
    assert td.TRAINING_PREPROCESSING == recipe.PREPROCESSING_VERSION
    assert td.MIN_HEAD_SAMPLES == gate.MIN_HEAD_SAMPLES
    assert td.MAX_ROWS == dataset.MAX_ROWS
    assert td.NO_CASE == dataset.NO_CASE
    expected = {h: {f: recipe.head_target(h, f) for f in dataset.FOLDERS
                    if recipe.head_target(h, f) is not None} for h in recipe.HEADS}
    assert td.HEAD_TARGETS == expected
    assert tuple(load("taxonomy").FOLDERS) == dataset.FOLDERS


def test_the_export_file_reads_back_through_the_real_reader(td, tmp_path):
    rng = np.random.default_rng(0)
    rows = []
    for i, folder in enumerate(f for f in dataset.FOLDERS for _ in range(8)):
        case_id = None if i % 3 == 0 else (5 if i == 4 else 100 + i)  # 4 and 5 share case 5 / none
        rows.append((folder, rng.normal(size=768).tolist(), rng.normal(size=768).tolist(), case_id))
    rows[5] = (*rows[5][:3], 5)
    path = tmp_path / "dataset.npz"
    path.write_bytes(td.build_dataset(rows))
    d = dataset.read_dataset(path)
    assert d.embeddings.shape == d.campaign_embeddings.shape == (64, 768)
    assert np.allclose(d.embeddings[1], np.float32(rows[1][1]))
    assert d.folders.tolist() == [r[0] for r in rows]
    assert d.case_ids[0] == dataset.NO_CASE and d.case_ids[4] == 5 and d.case_ids[5] == dataset.NO_CASE
    assert (d.case_ids == dataset.NO_CASE).sum() == 23  # 22 rows without a case + the duplicate
