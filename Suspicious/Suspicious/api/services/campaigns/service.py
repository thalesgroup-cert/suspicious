"""
CampaignQueryService: business logic for the campaigns endpoints that are not the summary or the neighbours (PCA, classification counts, mail volume).

Each method returns the raw payload dict that the corresponding view
serializes back to the client, keeping views thin.
"""
import logging
from datetime import date, datetime, time, timedelta, timezone as dt_timezone
from typing import Any, Dict, List, Sequence, Tuple

import numpy as np
from django.core.cache import cache

from .chroma import (
    fetch_records_for_ids,
    get_chroma_collection,
    iter_metadata_dicts,
    select_deterministic_sample_ids,
    stable_id_score,
)
from .metadata import (
    CLASSIFICATION_DANGEROUS,
    COUNT_BUCKETS,
    classification_bucket_for_counts,
    coerce_dict,
    extract_case_id,
    extract_mail_subject,
    extract_metadata_datetime,
    normalize_classification,
    parse_source_refs,
)

logger = logging.getLogger(__name__)

DEFAULT_PCA_LIMIT = 1500
MAX_PCA_LIMIT = 5000
PCA_COMPONENTS = 3
DEFAULT_PERIOD_DAYS = 15
MIN_PERIOD_DAYS = 7
MAX_PERIOD_DAYS = 90
MAIL_VOLUME_CACHE_TTL_SECONDS = 120


def empty_counts_payload() -> Dict[str, int]:
    return {bucket: 0 for bucket in COUNT_BUCKETS}


def empty_pca_payload() -> Dict[str, Any]:
    return {
        "points": [],
        "explained_variance": [0.0] * PCA_COMPONENTS,
    }


def empty_mail_volume_payload(days: Sequence[date]) -> Dict[str, Any]:
    return {
        "dates": list(days),
        "non_danger": [0] * len(days),
        "dangerous": [0] * len(days),
        "campaigns": [],
    }


def format_campaign_name(source_refs: Tuple[str, ...], fallback_index: int) -> str:
    if not source_refs:
        return f"Campaign {fallback_index}"
    if len(source_refs) <= 3:
        return ", ".join(source_refs)
    return ", ".join(source_refs[:3]) + "…"


def select_dominant_dim_vectors(
    records: Sequence[Tuple[str, Any, Dict[str, Any]]],
) -> Tuple[List[Tuple[str, np.ndarray, Dict[str, Any]]], int, int]:
    """Finite float64 vectors of the most common dimension (larger dim on ties),
    sorted by stable id score; plus (skipped_empty, skipped_invalid) counts."""
    dim_buckets: Dict[int, List[Tuple[str, np.ndarray, Dict[str, Any]]]] = {}
    skipped_empty = 0
    skipped_invalid = 0

    for row_id, embedding, metadata in records:
        if embedding is None:
            skipped_empty += 1
            continue

        try:
            vector = np.asarray(embedding, dtype=np.float64).reshape(-1)
        except Exception:
            skipped_invalid += 1
            continue

        if vector.size == 0 or not np.all(np.isfinite(vector)):
            skipped_invalid += 1
            continue

        dim_buckets.setdefault(int(vector.size), []).append((row_id, vector, metadata))

    if not dim_buckets:
        return [], skipped_empty, skipped_invalid

    chosen_dim = max(dim_buckets.keys(), key=lambda dim: (len(dim_buckets[dim]), dim))
    selected = dim_buckets[chosen_dim]
    selected.sort(key=lambda item: stable_id_score(item[0]))
    return selected, skipped_empty, skipped_invalid


def fetch_dominant_sample(collection, limit: int):
    """The deterministic sample shared by PCA and neighbours:
    (sampled_ids, dominant-dimension vectors, skipped_empty, skipped_invalid)."""
    sampled_ids = select_deterministic_sample_ids(collection, min(limit, MAX_PCA_LIMIT))
    if not sampled_ids:
        return [], [], 0, 0
    selected, skipped_empty, skipped_invalid = select_dominant_dim_vectors(
        fetch_records_for_ids(collection, sampled_ids)
    )
    return sampled_ids, selected, skipped_empty, skipped_invalid


class CampaignQueryService:
    """Encapsulates the queries that back the campaigns endpoints."""

    def get_classification_counts(self) -> Dict[str, int]:
        collection = get_chroma_collection()
        if collection is None:
            return empty_counts_payload()

        counts = empty_counts_payload()
        scanned = 0

        try:
            for meta in iter_metadata_dicts(collection):
                scanned += 1
                bucket = classification_bucket_for_counts(meta.get("classification"))
                if bucket is not None:
                    counts[bucket] += 1

            logger.debug(
                "Campaign classification counts computed from %s metadata rows.",
                scanned,
            )
        except Exception as exc:
            logger.error("Error computing campaign classification counts: %s", exc, exc_info=True)
            return empty_counts_payload()

        return counts

    def get_pca(self, limit: int) -> Dict[str, Any]:
        collection = get_chroma_collection()
        if collection is None:
            return empty_pca_payload()

        try:
            sampled_ids, selected, skipped_empty, skipped_invalid = fetch_dominant_sample(
                collection, limit
            )
            if not sampled_ids:
                return empty_pca_payload()

            if not selected:
                logger.warning(
                    "PCA sampling yielded no valid embeddings. sampled_ids=%s skipped_empty=%s skipped_invalid=%s",
                    len(sampled_ids),
                    skipped_empty,
                    skipped_invalid,
                )
                return empty_pca_payload()
            chosen_dim = selected[0][1].size

            vectors = [item[1] for item in selected]
            metas = [item[2] for item in selected]

            # One SVD path covers the degenerate inputs too: a single vector or
            # identical vectors centre to zeros (denom 0 -> zero ratios), 1-dim
            # vectors yield one component, 2 vectors at most two; missing
            # components are padded with 0.0 so x/y/z and 3 ratios always exist.
            X = np.stack(vectors, axis=0)
            X_centered = X - X.mean(axis=0, keepdims=True)

            try:
                _, singular_values, vt = np.linalg.svd(X_centered, full_matrices=False)
            except Exception as exc:
                logger.error("PCA SVD failed: %s", exc, exc_info=True)
                return empty_pca_payload()

            # SVD signs are arbitrary: make each component's largest-magnitude
            # loading positive so the map does not mirror between refreshes.
            components = vt[:PCA_COMPONENTS].copy()
            for row in components:
                if row[np.argmax(np.abs(row))] < 0:
                    row *= -1.0

            scores = np.zeros((X_centered.shape[0], PCA_COMPONENTS))
            projected = X_centered @ components.T
            scores[:, :projected.shape[1]] = projected

            eigenvalue_numerators = np.square(singular_values)
            denom = float(eigenvalue_numerators.sum())
            ratios = [0.0] * PCA_COMPONENTS
            if denom > 0.0:
                for i, value in enumerate(eigenvalue_numerators[:PCA_COMPONENTS]):
                    ratios[i] = float(value / denom)

            points = []
            for idx, meta in enumerate(metas):
                sent_dt = extract_metadata_datetime(meta)
                points.append({
                    "x": float(scores[idx, 0]),
                    "y": float(scores[idx, 1]),
                    "z": float(scores[idx, 2]),
                    "label": normalize_classification(meta.get("classification")),
                    "suspicious_case_id": extract_case_id(meta),
                    "mail_subject": extract_mail_subject(meta),
                    "sourceRefs": list(parse_source_refs(meta.get("sourceRefs"))),
                    "date": (
                        sent_dt.astimezone(dt_timezone.utc).date().isoformat()
                        if sent_dt is not None else None
                    ),
                })

            logger.debug(
                "Campaign PCA computed. requested_limit=%s sampled_ids=%s valid_vectors=%s chosen_dim=%s",
                limit,
                len(sampled_ids),
                len(vectors),
                chosen_dim,
            )

            return {
                "points": points,
                "explained_variance": ratios,
            }

        except Exception as exc:
            logger.error("Error computing PCA points: %s", exc, exc_info=True)
            return empty_pca_payload()

    def get_mail_volume(self, days: int = DEFAULT_PERIOD_DAYS) -> Dict[str, Any]:
        key = f"campaigns:mail-volume:{days}"
        cached = cache.get(key)
        if cached is not None:
            return cached

        today_utc = datetime.now(dt_timezone.utc).date()
        start_utc = today_utc - timedelta(days=days - 1)
        all_days = [start_utc + timedelta(days=i) for i in range(days)]
        day_index = {day: idx for idx, day in enumerate(all_days)}

        collection = get_chroma_collection()
        if collection is None:
            return empty_mail_volume_payload(all_days)

        non_danger = [0] * len(all_days)
        dangerous = [0] * len(all_days)
        campaign_windows: Dict[Tuple[str, ...], Dict[str, datetime]] = {}

        scanned = 0
        skipped_no_date = 0

        try:
            for meta in iter_metadata_dicts(collection):
                scanned += 1
                meta = coerce_dict(meta)

                sent_dt = extract_metadata_datetime(meta)
                if sent_dt is None:
                    skipped_no_date += 1
                    continue

                sent_dt = sent_dt.astimezone(dt_timezone.utc)
                day = sent_dt.date()

                source_refs = parse_source_refs(meta.get("sourceRefs"))
                if source_refs:
                    window = campaign_windows.get(source_refs)
                    if window is None:
                        campaign_windows[source_refs] = {"first": sent_dt, "last": sent_dt}
                    else:
                        if sent_dt < window["first"]:
                            window["first"] = sent_dt
                        if sent_dt > window["last"]:
                            window["last"] = sent_dt

                if not (start_utc <= day <= today_utc):
                    continue

                pos = day_index.get(day)
                if pos is None:
                    continue

                classification = normalize_classification(meta.get("classification"))
                if classification == CLASSIFICATION_DANGEROUS:
                    dangerous[pos] += 1
                else:
                    non_danger[pos] += 1

            logger.debug(
                "Campaign mail volume computed from %s rows. skipped_no_date=%s campaign_groups=%s",
                scanned,
                skipped_no_date,
                len(campaign_windows),
            )

        except Exception as exc:
            logger.error("Error computing mail volume: %s", exc, exc_info=True)
            return empty_mail_volume_payload(all_days)

        window_start_dt = datetime.combine(start_utc, time.min, tzinfo=dt_timezone.utc)
        window_end_dt = datetime.combine(today_utc, time.max, tzinfo=dt_timezone.utc)

        campaigns_out: List[Dict[str, Any]] = []
        for idx_num, (source_refs, bounds) in enumerate(
            sorted(
                campaign_windows.items(),
                key=lambda item: (
                    item[1]["first"],
                    item[1]["last"],
                    item[0],
                ),
            ),
            start=1,
        ):
            start_dt = bounds.get("first")
            end_dt = bounds.get("last")
            if start_dt is None or end_dt is None:
                continue

            if end_dt < start_dt:
                start_dt, end_dt = end_dt, start_dt

            if end_dt < window_start_dt or start_dt > window_end_dt:
                continue

            clamped_start = max(start_dt, window_start_dt)
            clamped_end = min(end_dt, window_end_dt)
            if clamped_end < clamped_start:
                continue

            campaigns_out.append({
                "name": format_campaign_name(source_refs, idx_num),
                "start": clamped_start,
                "end": clamped_end,
            })

        payload = {
            "dates": all_days,
            "non_danger": non_danger,
            "dangerous": dangerous,
            "campaigns": campaigns_out,
        }
        cache.set(key, payload, MAIL_VOLUME_CACHE_TTL_SECONDS)
        return payload
