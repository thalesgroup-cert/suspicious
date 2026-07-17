"""
MISP deduplication helpers — unchanged logic, extracted for clarity.
"""
from __future__ import annotations


def has_attribute(event: dict, attr_type: str, value: str) -> bool:
    for attr in event.get("Attribute", []):
        if attr["type"] == attr_type and attr["value"] == value:
            return True
    return False


def has_object(event: dict, object_name: str, unique_value: str) -> bool:
    for obj in event.get("Object", []):
        if obj["name"] != object_name:
            continue
        for attr in obj.get("Attribute", []):
            if attr.get("value") == unique_value:
                return True
    return False