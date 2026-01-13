import logging
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)

DETECTION_TAGS = {
    'Safe': 'level::SAFE',
    'Inconclusive': 'level::INCONCLUSIVE',
    'Suspicious': 'level::SUSPICIOUS',
    'Dangerous': 'level::DANGEROUS'
}

def get_detection_level_tag(detection_level: str) -> str:
    return DETECTION_TAGS.get(detection_level.capitalize(), '')


def parse_tags(tags_config: dict) -> list[dict]:
    tags = []
    for key, value in tags_config.items():
        if isinstance(value, str):
            for tag in value.split(','):
                tag = tag.strip()
                tags.append({"name": f"{key}:{tag}"} if key != "other" else {"name": tag})
        elif isinstance(value, dict):
            for subkey, subval in value.items():
                tags.append({"name": f'{key}:{subkey}="{subval}"'})
    return tags

def add_case_number_attribute(misp, event: dict, case_number: Any) -> None:
    case_number_attribute = {
        'type': 'text',
        'value': str(case_number),
        'category': 'Other',
        'comment': 'Case Number'
    }
    misp.add_attribute(event['id'], case_number_attribute)


def clean_subject(subject: str) -> str:
    return subject.replace("\n", " ").replace("\r", "")


def current_month_event_name(prefix: str = "MalSpam cases") -> str:
    return f"{prefix} - {datetime.now().strftime('%B %Y')}"


def first_day_of_month() -> str:
    return datetime.now().strftime("%Y-%m-01")
