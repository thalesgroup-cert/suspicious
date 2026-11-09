"""Django cannot import torch, so ai_model.registry keeps its own copy of the bundle file names.
This test (the only place both sides are importable) keeps the copy honest."""
import ast
from pathlib import Path

import pytest

REGISTRY = Path(__file__).resolve().parents[3] / "Suspicious/Suspicious/ai_model/registry.py"


def registry_names():
    for node in ast.parse(REGISTRY.read_text()).body:
        if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "") == "BUNDLE_FILE_NAMES":
            return ast.literal_eval(node.value)
    raise AssertionError("BUNDLE_FILE_NAMES not found")


@pytest.mark.skipif(not REGISTRY.exists(), reason="Django tree not next to the analyzer")
def test_registry_file_names_match_training_bundle():
    from training.bundle import BUNDLE_FILES, MANIFEST

    assert set(registry_names()) == {*BUNDLE_FILES, MANIFEST}
    assert len(registry_names()) == len(BUNDLE_FILES) + 1
