"""The review-folder taxonomy (Plan D, ruling D1): the class is the digit prefix."""

FOLDERS: tuple[str, ...] = (
    "0_LEGIT_INTERNAL_COMMUNICATION",
    "0_LEGIT_EXTERNAL_COMMUNICATION",
    "1_SPAM",
    "1_NEWSLETTER",
    "2_CLASSIC_PHISHING",
    "2_CLONE_PHISHING",
    "2_BLACKMAILING_PHISHING",
    "2_WHALING_PHISHING",
)

_PREFIX = {"0": "Safe", "1": "Unwanted", "2": "Dangerous"}


def class_of(folder: str) -> str | None:
    """Safe, Unwanted or Dangerous for a known folder name, else None."""
    return _PREFIX.get(folder[0]) if folder in FOLDERS else None
