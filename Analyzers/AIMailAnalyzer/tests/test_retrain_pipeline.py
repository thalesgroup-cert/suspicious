"""
Regression tests for the "retrain model monthly" pipeline's label taxonomy.

No torch/sentence_transformers required - these only check that
Re_Train_Model/variable.py's per-model class counts and encoding order still
match mail_analysis.MODEL_SPECS / SubClassificationName. This is exactly the
kind of drift that previously produced a 5-class dangerous encoder for a
4-output production model (silent shape mismatch at load time) and a wrong
CLASSIC/WHALING/CLONE/BLACKMAIL ordering (silently wrong phishing subtype
labels even when the model itself was accurate).
"""
import sys
from pathlib import Path

_ANALYZER_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ANALYZER_ROOT))
sys.path.insert(0, str(_ANALYZER_ROOT / "retrain model monthly"))

import mail_analysis  # noqa: E402
from Re_Train_Model import variable  # noqa: E402


def _output_dim(model_filename_prefix):
    spec = next(s for s in mail_analysis.MODEL_SPECS if s.filename.startswith(model_filename_prefix))
    return spec.output_dim


def test_dangerous_encoder_has_exactly_four_classes():
    """dangerous_30_epochs_model has 4 output neurons - the encoder must
    never define a 5th class (e.g. a reintroduced SPEAR_PHISHING) without the
    production model being retrained to match."""
    encoded_values = {
        variable.y_dangerous_encoder([label])[0] for label in variable.dangerous_folders
    }
    assert len(encoded_values) == _output_dim("dangerous_")
    assert encoded_values == {0, 1, 2, 3}


def test_dangerous_encoder_order_matches_subclassification_name():
    """Local index i for folder X must equal
    SubClassificationName[X's production name].value - 4 (the dangerous
    sub-model's offset in the concatenated sub-classification vector)."""
    expected = {
        "2_CLASSIC_PHISHING": mail_analysis.SubClassificationName.CLASSIC_PHISHING.value,
        "2_CLONE_PHISHING": mail_analysis.SubClassificationName.CLONE.value,
        "2_BLACKMAILING_PHISHING": mail_analysis.SubClassificationName.BLACKMAIL.value,
        "2_WHALING_PHISHING": mail_analysis.SubClassificationName.WHALING.value,
    }
    offset = min(expected.values())
    for folder, global_value in expected.items():
        local_index = variable.y_dangerous_encoder([folder])[0]
        assert local_index == global_value - offset, folder


def test_safe_encoder_matches_subclassification_name():
    assert variable.y_safe_encoder(["0_LEGIT_INTERNAL_COMMUNICATION"])[0] == \
        mail_analysis.SubClassificationName.INTERNAL.value
    assert variable.y_safe_encoder(["0_LEGIT_EXTERNAL_COMMUNICATION"])[0] == \
        mail_analysis.SubClassificationName.EXTERNAL.value


def test_unwanted_encoder_matches_subclassification_name_offset():
    """Trained/named after unwanted_30_epochs_model.pth, but the function in
    variable.py kept its original name y_suspicious_encoder."""
    offset = mail_analysis.SubClassificationName.SPAM.value
    assert variable.y_suspicious_encoder(["1_SPAM"])[0] == \
        mail_analysis.SubClassificationName.SPAM.value - offset
    assert variable.y_suspicious_encoder(["1_NEWSLETTER"])[0] == \
        mail_analysis.SubClassificationName.NEWSLETTER.value - offset


def test_every_model_name_used_by_trainers_exists_in_model_specs():
    """Needs pandas/torch (pulled in transitively via Re_Train_Model.utils),
    unlike the tests above - skip when the ML stack isn't installed, matching
    test_mail_analysis.py's approach for the same constraint."""
    import pytest
    pytest.importorskip("pandas")
    pytest.importorskip("torch")

    from Re_Train_Model.train_dangerous_model import DangerousTrainer
    from Re_Train_Model.train_safe_model import SafeTrainer
    from Re_Train_Model.train_suspicious_model import Unwanted_Trainer
    from Re_Train_Model.train_safe_suspicious_model import Safe_Suspicious_Trainer
    from Re_Train_Model.train_spam_dangerous_model import Spam_Dangerous_Trainer
    from Re_Train_Model.utils import num_classes_for

    trainers = [
        DangerousTrainer, SafeTrainer, Unwanted_Trainer,
        Safe_Suspicious_Trainer, Spam_Dangerous_Trainer,
    ]
    spec_filenames = {spec.filename for spec in mail_analysis.MODEL_SPECS}
    assert len(trainers) == len(spec_filenames)
    for trainer_cls in trainers:
        assert f"{trainer_cls.MODEL_NAME}.pth" in spec_filenames
        assert num_classes_for(trainer_cls.MODEL_NAME) > 0
