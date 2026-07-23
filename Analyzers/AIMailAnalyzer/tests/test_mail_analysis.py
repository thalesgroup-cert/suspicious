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


def test_get_classification_breakdown_labels_by_enum_name():
    breakdown = mail_analysis.get_classification_breakdown([0.7, 0.2, 0.1])
    assert breakdown == {"SAFE": 0.7, "UNWANTED": 0.2, "DANGEROUS": 0.1}


def test_get_sub_classification_breakdown_labels_by_enum_name():
    breakdown = mail_analysis.get_sub_classification_breakdown(
        [0.1, 0.05, 0.2, 0.05, 0.5, 0.05, 0.03, 0.02]
    )
    assert breakdown["WHALING"] == 0.02
    assert breakdown["CLASSIC_PHISHING"] == 0.5
    assert len(breakdown) == len(mail_analysis.SubClassificationName)


def test_split_into_sentences_caps_at_max_sentences():
    body = ". ".join(f"sentence {i}" for i in range(100)) + "."
    sentences = mail_analysis.split_into_sentences(body, max_sentences=10)
    assert len(sentences) == 10


def test_split_into_sentences_drops_blank_chunks():
    sentences = mail_analysis.split_into_sentences("Hello world.  \n\n  Second sentence!")
    assert sentences == ["Hello world.", "Second sentence!"]


def test_rank_phrase_impacts_keeps_only_positive_impact_sorted_desc():
    sentences = ["a", "b", "c", "d"]
    impacts = [0.1, -0.05, 0.4, 0.0]
    ranked = mail_analysis.rank_phrase_impacts(sentences, impacts, top_n=5)
    assert ranked == [
        {"text": "c", "impact": 0.4},
        {"text": "a", "impact": 0.1},
    ]


def test_rank_phrase_impacts_respects_top_n():
    sentences = ["a", "b", "c"]
    impacts = [0.3, 0.2, 0.1]
    ranked = mail_analysis.rank_phrase_impacts(sentences, impacts, top_n=2)
    assert len(ranked) == 2
    assert ranked[0]["text"] == "a"
