"""
Campaign summary: period KPIs and campaigns computed in one metadata scan.

A "campaign" is a heuristic: the messages whose parsed `sourceRefs` are
identical. Messages without source refs belong to no campaign.
"""
import logging
from datetime import datetime, timedelta, timezone as dt_timezone
from typing import Any, Dict, List, Optional

from django.core.cache import cache

from .chroma import get_chroma_collection, iter_metadata_dicts
from .metadata import (
    CLASSIFICATION_DANGEROUS,
    classification_bucket_for_counts,
    extract_case_id,
    extract_mail_subject,
    extract_metadata_datetime,
    normalize_classification,
    parse_source_refs,
)
from .service import empty_counts_payload, format_campaign_name

logger = logging.getLogger(__name__)

ACTIVE_WINDOW_HOURS = 48
MAX_CASE_IDS = 20
MAX_CAMPAIGNS = 200
CACHE_TTL_SECONDS = 120


def _now() -> datetime:
    return datetime.now(dt_timezone.utc)


def _share(part: int, whole: int) -> Optional[float]:
    # None = no messages, so no share (the UI shows "no data")
    return part / whole if whole else None


def _empty_payload(days, start, end) -> Dict[str, Any]:
    return {
        "days": days,
        "period": {"start": start, "end": end},
        "messages": 0,
        "previous_messages": 0,
        "dangerous": 0,
        "previous_dangerous": 0,
        "dangerous_share": None,
        "previous_dangerous_share": None,
        "peak_day": None,
        "mix": empty_counts_payload(),
        "unclassified": 0,
        "campaigns": [],
        "campaigns_total": 0,
        "max_case_ids": MAX_CASE_IDS,
        "active_campaigns": 0,
        "active_window_hours": ACTIVE_WINDOW_HOURS,
        "largest_campaign": None,
    }


def get_campaign_summary(days: int) -> Dict[str, Any]:
    key = f"campaigns:summary:{days}"
    cached = cache.get(key)
    if cached is not None:
        return cached

    now = _now()
    end = now.date()
    start = end - timedelta(days=days - 1)
    prev_start = start - timedelta(days=days)
    payload = _empty_payload(days, start, end)

    collection = get_chroma_collection()
    if collection is None:
        return payload

    per_day: Dict[Any, int] = {}
    groups: Dict[tuple, Dict[str, Any]] = {}

    try:
        for meta in iter_metadata_dicts(collection):
            sent_dt = extract_metadata_datetime(meta)
            if sent_dt is None:
                continue
            sent_dt = sent_dt.astimezone(dt_timezone.utc)
            day = sent_dt.date()
            is_dangerous = (
                normalize_classification(meta.get("classification")) == CLASSIFICATION_DANGEROUS
            )

            if prev_start <= day < start:
                payload["previous_messages"] += 1
                payload["previous_dangerous"] += is_dangerous
                continue
            if not (start <= day <= end):
                continue

            payload["messages"] += 1
            payload["dangerous"] += is_dangerous
            per_day[day] = per_day.get(day, 0) + 1
            bucket = classification_bucket_for_counts(meta.get("classification"))
            if bucket is not None:
                payload["mix"][bucket] += 1

            refs = parse_source_refs(meta.get("sourceRefs"))
            if not refs:
                continue
            group = groups.setdefault(refs, {"seen": [], "dangerous": 0, "subject": None})
            group["seen"].append((sent_dt, extract_case_id(meta)))
            group["dangerous"] += is_dangerous
            subject = extract_mail_subject(meta)
            if subject and (group["subject"] is None or sent_dt < group["subject"][0]):
                group["subject"] = (sent_dt, subject)
    except Exception as exc:
        logger.error("Error computing campaign summary: %s", exc, exc_info=True)
        return _empty_payload(days, start, end)  # never the half-filled one, never cached

    payload["unclassified"] = payload["messages"] - sum(payload["mix"].values())

    payload["dangerous_share"] = _share(payload["dangerous"], payload["messages"])
    payload["previous_dangerous_share"] = _share(
        payload["previous_dangerous"], payload["previous_messages"]
    )
    if per_day:
        peak = min(per_day.items(), key=lambda item: (-item[1], item[0]))
        payload["peak_day"] = {"date": peak[0], "count": peak[1]}

    active_since = now - timedelta(hours=ACTIVE_WINDOW_HOURS)
    campaigns: List[Dict[str, Any]] = []
    for refs, group in groups.items():
        seen = sorted(group["seen"], key=lambda item: item[0])
        case_ids: List[str] = []
        # most recent 20, newest first; (date, id) makes ties stable
        for _, case_id in sorted(seen, key=lambda item: (item[0], item[1] or ""), reverse=True):
            if case_id and case_id not in case_ids:
                case_ids.append(case_id)
                if len(case_ids) == MAX_CASE_IDS:
                    break
        messages = len(seen)
        campaigns.append({
            "name": format_campaign_name(refs, 0),
            "first_seen": seen[0][0],
            "last_seen": seen[-1][0],
            "messages": messages,
            "dangerous": group["dangerous"],
            "dangerous_share": _share(group["dangerous"], messages),
            "sample_subject": group["subject"][1] if group["subject"] else None,
            "case_ids": case_ids,
            "active": seen[-1][0] >= active_since,
        })
    # largest first; ties: the most recently seen, then the name (a stable order for the cut below)
    campaigns.sort(key=lambda c: (-c["messages"], -c["last_seen"].timestamp(), c["name"]))

    # Counted over every campaign; only the list is cut, so one message per distinct source-ref set cannot
    # grow the cached, re-validated payload without bound.
    payload["campaigns_total"] = len(campaigns)
    payload["active_campaigns"] = sum(c["active"] for c in campaigns)
    if campaigns:
        payload["largest_campaign"] = {
            "name": campaigns[0]["name"], "messages": campaigns[0]["messages"]
        }
    payload["campaigns"] = campaigns[:MAX_CAMPAIGNS]

    cache.set(key, payload, CACHE_TTL_SECONDS)
    return payload
