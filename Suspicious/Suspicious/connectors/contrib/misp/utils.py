# misp/utils.py
"""
MISP utility helpers.
"""
from __future__ import annotations
import logging
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)

DETECTION_TAGS: dict[str, str] = {
    "Safe":         "level::SAFE",
    "Inconclusive": "level::INCONCLUSIVE",
    "Suspicious":   "level::SUSPICIOUS",
    "Dangerous":    "level::DANGEROUS",
}

# Verdict strings that warrant pushing to the secondary monthly event
SECONDARY_MISP_LEVELS = {"Suspicious", "Dangerous"}


def get_detection_level_tag(detection_level: str) -> str:
    """Return the MISP tag string for a case verdict, or '' if unknown."""
    return DETECTION_TAGS.get(detection_level.capitalize(), "")


def parse_tags(tags_config: dict) -> list[dict]:
    tags: list[dict] = []
    for key, value in tags_config.items():
        if isinstance(value, str):
            for tag in value.split(","):
                tag = tag.strip()
                tags.append({"name": "%s:%s" % (key, tag)} if key != "other" else {"name": tag})
        elif isinstance(value, dict):
            for subkey, subval in value.items():
                tags.append({"name": '%s:%s="%s"' % (key, subkey, subval)})
    return tags


def add_case_number_attribute(misp_instance, event_id: str, case_number: Any) -> None:
    """Add a plain-text case-number attribute to an existing MISP event."""
    misp_instance.add_attribute(event_id, {
        "type":     "text",
        "value":    str(case_number),
        "category": "Other",
        "comment":  "Case Number",
    })


def clean_subject(subject: str) -> str:
    return subject.replace("\n", " ").replace("\r", "")


def current_month_event_name(prefix: str = "MalSpam cases") -> str:
    return "%s - %s" % (prefix, datetime.now().strftime("%B %Y"))


def first_day_of_month() -> str:
    return datetime.now().strftime("%Y-%m-01")