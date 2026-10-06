import numpy as np

# IMAP mailbox folder names == taxonomy labels. Analysts file each reviewed
# "challenged" mail into the matching folder, which is what makes this the
# ground-truth source for retraining (see generator_dataset.py).
#
# 2_SPEAR_PHISHING is intentionally absent: the deployed dangerous_30_epochs_model
# has 4 output neurons (mail_analysis.MODEL_SPECS), matching SubClassificationName's
# CLASSIC_PHISHING/CLONE/BLACKMAIL/WHALING. Adding a 5th class means retraining
# with a new output_dim AND updating mail_analysis.SubClassificationName /
# MODEL_SPECS in the production analyzer - out of scope for this drop-in pipeline.
folders = [
    "0_LEGIT_INTERNAL_COMMUNICATION",
    "0_LEGIT_EXTERNAL_COMMUNICATION",
    "1_SPAM",
    "1_NEWSLETTER",
    "2_CLASSIC_PHISHING",
    "2_WHALING_PHISHING",
    "2_CLONE_PHISHING",
    "2_BLACKMAILING_PHISHING",
]

# ============================================================
# Main classification (safe vs suspicious vs dangerous)
# ============================================================

labels_safe_suspicious = {
    "0_LEGIT_INTERNAL_COMMUNICATION": "safe",
    "0_LEGIT_EXTERNAL_COMMUNICATION": "safe",
    "1_SPAM": "suspicious",
    "1_NEWSLETTER": "suspicious",
    "2_CLASSIC_PHISHING": "suspicious",
    "2_WHALING_PHISHING": "suspicious",
    "2_CLONE_PHISHING": "suspicious",
    "2_BLACKMAILING_PHISHING": "suspicious",
}

labels_spam_dangerous = {
    "0_LEGIT_INTERNAL_COMMUNICATION": np.nan,
    "0_LEGIT_EXTERNAL_COMMUNICATION": np.nan,
    "1_SPAM": "spam",
    "1_NEWSLETTER": "spam",
    "2_CLASSIC_PHISHING": "dangerous",
    "2_WHALING_PHISHING": "dangerous",
    "2_CLONE_PHISHING": "dangerous",
    "2_BLACKMAILING_PHISHING": "dangerous",
}


def y_safe_suspcious_encoder(y):
    encoding_map = {"safe": 0, "suspicious": 1}
    return np.array([encoding_map[label] for label in y])


def y_spam_dangerous_encoder(y):
    encoding_map = {"spam": 0, "dangerous": 1}
    return np.array([encoding_map[label] for label in y])


# ============================================================
# Sub-classification: SAFE (internal vs external)
# ============================================================

safe_folders = {
    "0_LEGIT_INTERNAL_COMMUNICATION": "0_LEGIT_INTERNAL_COMMUNICATION",
    "0_LEGIT_EXTERNAL_COMMUNICATION": "0_LEGIT_EXTERNAL_COMMUNICATION",
}


def y_safe_encoder(y):
    """INTERNAL=0, EXTERNAL=1 - must match SubClassificationName.INTERNAL/EXTERNAL (0/1)."""
    encoding_map = {
        "0_LEGIT_INTERNAL_COMMUNICATION": 0,
        "0_LEGIT_EXTERNAL_COMMUNICATION": 1,
    }
    return np.array([encoding_map[label] for label in y], dtype=np.int64)


# ============================================================
# Sub-classification: UNWANTED / suspicious (spam vs newsletter)
# ============================================================

suspicious_folders = {
    "1_SPAM": "1_SPAM",
    "1_NEWSLETTER": "1_NEWSLETTER",
}


def y_suspicious_encoder(y):
    """SPAM=0, NEWSLETTER=1 - must match SubClassificationName.SPAM/NEWSLETTER (2/3, offset by main model)."""
    encoding_map = {
        "1_SPAM": 0,
        "1_NEWSLETTER": 1,
    }
    return np.array([encoding_map[label] for label in y], dtype=np.int64)


# ============================================================
# Sub-classification: DANGEROUS (phishing subtype)
# ============================================================

dangerous_folders = {
    "2_CLASSIC_PHISHING": "2_CLASSIC_PHISHING",
    "2_CLONE_PHISHING": "2_CLONE_PHISHING",
    "2_BLACKMAILING_PHISHING": "2_BLACKMAILING_PHISHING",
    "2_WHALING_PHISHING": "2_WHALING_PHISHING",
}

labels_dangerous = dict(dangerous_folders)


def y_dangerous_encoder(y):
    """
    Order matters: ai_mail_classifier.py concatenates
    [safe_model(2), unwanted_model(2), dangerous_model(4)] outputs and argmaxes
    against the flat SubClassificationName enum (CLASSIC_PHISHING=4, CLONE=5,
    BLACKMAIL=6, WHALING=7). The dangerous model's 4 output neurons must be in
    that exact relative order (0,1,2,3 == enum 4,5,6,7), or argmax will report
    the wrong phishing subtype even when the model is otherwise accurate.
    """
    encoding_map = {
        "2_CLASSIC_PHISHING": 0,
        "2_CLONE_PHISHING": 1,
        "2_BLACKMAILING_PHISHING": 2,
        "2_WHALING_PHISHING": 3,
    }
    return np.array([encoding_map[label] for label in y], dtype=np.int64)
