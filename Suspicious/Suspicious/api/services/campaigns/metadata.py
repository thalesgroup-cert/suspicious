"""
Pure metadata-extraction helpers used by the campaigns endpoints.

These operate on raw Python dicts and have no ChromaDB or Django dependency,
so they can be unit-tested without a running collection.
"""
import ast
import json
import re
from datetime import datetime, timezone as dt_timezone
from email.utils import parsedate_to_datetime
from typing import Any, Dict, List, Optional, Tuple

from score_process.score_utils.thehive.utils import (
    parse_and_decode_defaultdict,
    parse_headers,
)


DATE_METADATA_KEYS = (
    "sent_date",
    "date",
    "received_at",
    "created_at",
    "created",
    "timestamp",
    "date_received",
    "mail_date",
    "headers_date",
    "date_header",
    "ingested_at",
    "submitted_at",
    "time",
    "ts",
)

HEADER_DATE_KEYS = (
    "Date",
    "date",
    "Sent",
    "Sent-Date",
    "Sent-date",
    "sent_date",
)

CLASSIFICATION_SAFE = "SAFE"
CLASSIFICATION_UNWANTED = "UNWANTED"
CLASSIFICATION_SUSPICIOUS = "SUSPICIOUS"
CLASSIFICATION_DANGEROUS = "DANGEROUS"
CLASSIFICATION_UNKNOWN = "UNKNOWN"

MAIL_SUBJECT_KEYS = (
    "subject",
    "mail_subject",
    "email_subject",
    "Subject",
)


def coerce_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    try:
        return list(value)
    except TypeError:
        return [value]


def coerce_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def normalize_classification(value: Any) -> str:
    text = str(value or "").strip().upper()
    if not text:
        return CLASSIFICATION_UNKNOWN
    return text


def classification_bucket_for_counts(value: Any) -> Optional[str]:
    label = normalize_classification(value)
    if label == CLASSIFICATION_SAFE:
        return CLASSIFICATION_SAFE
    if label in (CLASSIFICATION_UNWANTED, CLASSIFICATION_SUSPICIOUS):
        return CLASSIFICATION_UNWANTED
    if label == CLASSIFICATION_DANGEROUS:
        return CLASSIFICATION_DANGEROUS
    return None


def parse_source_refs(raw: Any) -> Tuple[str, ...]:
    if raw is None:
        return ()

    iterable: Optional[List[Any]] = None

    if isinstance(raw, (list, tuple, set)):
        iterable = list(raw)
    else:
        text = str(raw).strip()
        if not text:
            return ()

        for parser in (json.loads, ast.literal_eval):
            try:
                parsed = parser(text)
            except Exception:
                continue
            if isinstance(parsed, (list, tuple, set)):
                iterable = list(parsed)
                break
            if isinstance(parsed, str):
                iterable = [parsed]
                break

        if iterable is None:
            stripped = text.strip("[](){}")
            if not stripped:
                return ()
            parts = [segment for segment in re.split(r"[;,]", stripped) if segment]
            iterable = [seg.strip().strip("'\"") for seg in parts]

    if not iterable:
        return ()

    cleaned: List[str] = []
    seen = set()
    for item in iterable:
        value = str(item).strip().strip("'\"")
        if value and value not in seen:
            seen.add(value)
            cleaned.append(value)

    return tuple(sorted(cleaned))


def extract_headers_dict(raw: Any) -> Optional[Dict[str, Any]]:
    if not raw:
        return None
    if isinstance(raw, dict):
        return raw

    text = str(raw).strip()
    if not text:
        return None

    if "defaultdict" in text:
        try:
            parsed = parse_and_decode_defaultdict(text)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass

    for parser in (json.loads, ast.literal_eval):
        try:
            parsed = parser(text)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            continue

    try:
        parsed = parse_headers(text)
        if isinstance(parsed, dict):
            return dict(parsed)
    except Exception:
        pass

    return None


def parse_to_utc_datetime(value: Any) -> Optional[datetime]:
    if value is None:
        return None

    try:
        if isinstance(value, (int, float)):
            ts = float(value)
            if ts > 1e12:
                ts = ts / 1000.0
            return datetime.fromtimestamp(ts, tz=dt_timezone.utc)

        text = str(value).strip()
        if not text:
            return None

        try:
            parsed = parsedate_to_datetime(text)
            if parsed is not None:
                if parsed.tzinfo is None:
                    return parsed.replace(tzinfo=dt_timezone.utc)
                return parsed.astimezone(dt_timezone.utc)
        except Exception:
            pass

        normalized = text.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(normalized)
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=dt_timezone.utc)
            return parsed.astimezone(dt_timezone.utc)
        except Exception:
            pass

        date_match = re.search(r"(\d{4}-\d{2}-\d{2})", text)
        if date_match:
            parsed_date = datetime.fromisoformat(date_match.group(1))
            return parsed_date.replace(tzinfo=dt_timezone.utc)
    except Exception:
        return None

    return None


def extract_sent_datetime(meta: Dict[str, Any]) -> Optional[datetime]:
    headers_dict = extract_headers_dict(meta.get("headers"))
    if not headers_dict:
        return None

    candidates: List[Any] = []
    for key in HEADER_DATE_KEYS:
        value = headers_dict.get(key)
        if not value:
            continue
        if isinstance(value, (list, tuple)):
            candidates.extend(value)
        else:
            candidates.append(value)

    for candidate in candidates:
        parsed = parse_to_utc_datetime(candidate)
        if parsed is not None:
            return parsed

    return None


def extract_metadata_datetime(meta: Dict[str, Any]) -> Optional[datetime]:
    sent_dt = extract_sent_datetime(meta)
    if sent_dt is not None:
        return sent_dt

    for key in DATE_METADATA_KEYS:
        value = meta.get(key)
        if not value:
            continue
        parsed = parse_to_utc_datetime(value)
        if parsed is not None:
            return parsed

    for key, value in meta.items():
        if key in DATE_METADATA_KEYS or key == "headers":
            continue
        if not re.search(
            r"(date|time|timestamp|created|received|sent|submitted|ingested|ts)",
            str(key),
            re.IGNORECASE,
        ):
            continue
        parsed = parse_to_utc_datetime(value)
        if parsed is not None:
            return parsed

    return None


def extract_case_id(meta_obj: Any) -> Optional[str]:
    if not isinstance(meta_obj, dict):
        return None

    raw = meta_obj.get("suspicious_case_id")
    if raw is None:
        raw = meta_obj.get("case_id")
    if raw is None:
        return None

    if isinstance(raw, (list, tuple)):
        raw = raw[0] if raw else None
    if raw is None:
        return None

    text = str(raw).strip()
    return text or None


def extract_mail_subject(meta: Dict[str, Any]) -> Optional[str]:
    """
    Extract the mail subject from a ChromaDB metadata dict.

    Tries direct key lookups first, then parses the stored headers dict
    (which carries the RFC 2822 Subject header from the original email).
    Returns None — not an empty string — when nothing usable is found.
    """
    for key in MAIL_SUBJECT_KEYS:
        value = meta.get(key)
        if value and isinstance(value, str):
            stripped = value.strip()
            if stripped:
                return stripped

    headers_dict = extract_headers_dict(meta.get("headers"))
    if headers_dict:
        for key in ("Subject", "subject"):
            value = headers_dict.get(key)
            if isinstance(value, list):
                value = value[0] if value else None
            if value and isinstance(value, str):
                stripped = value.strip()
                if stripped:
                    return stripped

    return None
