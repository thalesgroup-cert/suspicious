"""The review-folder taxonomy (Plan D, ruling D1): the class is the digit prefix."""
import re

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


def canonical(folder: str) -> str | None:
    """The known folder a mailbox path names by its last hierarchy segment ("INBOX.1_SPAM" and
    "Review/1_SPAM" give "1_SPAM"), else None."""
    segment = re.split(r"[./]", folder or "")[-1]
    return segment if segment in FOLDERS else None


def class_of(folder: str) -> str | None:
    """Safe, Unwanted or Dangerous for a known folder (by its last segment), else None."""
    name = canonical(folder)
    return _PREFIX[name[0]] if name else None
