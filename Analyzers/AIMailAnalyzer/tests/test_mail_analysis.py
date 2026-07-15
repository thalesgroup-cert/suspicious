"""
Pure-logic regression tests for mail_analysis.py taxonomy/model-spec wiring.

No torch/sentence_transformers required — these two files are the only
thing in AIMailAnalyzer that don't need the ML stack to import, so this is
what's testable without the full Docker image.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import mail_analysis  # noqa: E402
import health  # noqa: E402


def test_subclassification_enum_matches_trained_model_capacity():
    """SubClassificationName must have exactly as many members as the
    safe/unwanted/dangerous sub-models can produce (argmax can never select
    an enum member beyond the concatenated probability array's length)."""
    sub_output_width = sum(
        spec.output_dim for spec in mail_analysis.MODEL_SPECS if spec.group == "sub"
    )
    assert len(mail_analysis.SubClassificationName) == sub_output_width


def test_dangerous_model_spec_has_four_outputs():
    dangerous = next(
        s for s in mail_analysis.MODEL_SPECS if s.filename.startswith("dangerous_")
    )
    assert dangerous.output_dim == 4


def test_health_probe_uses_the_same_model_specs_as_the_classifier():
    """health.py previously hardcoded output_dim=2 for every model, including
    the 4-output dangerous model, so load_state_dict always raised a shape
    mismatch there. Guard against a re-drifted, independently declared copy."""
    assert health.MODEL_SPECS is mail_analysis.MODEL_SPECS
