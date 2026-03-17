import ast
import hashlib
import heapq
import json
import logging
import os
import re
from datetime import date, datetime, time, timedelta, timezone as dt_timezone
from email.utils import parsedate_to_datetime
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

import numpy as np
from drf_spectacular.utils import (
    OpenApiExample,
    OpenApiParameter,
    OpenApiResponse,
    extend_schema,
)
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from api.serializers.campaigns import (
    CampaignClassificationCountsSerializer,
    CampaignMailVolumeResponseSerializer,
    CampaignPcaQuerySerializer,
    CampaignPcaResponseSerializer,
)
from score_process.score_utils.thehive.utils import (
    parse_and_decode_defaultdict,
    parse_headers,
)

logger = logging.getLogger(__name__)

DEFAULT_CHROMA_HOST = "chromadb"
DEFAULT_CHROMA_PORT = 8000
DEFAULT_CHROMA_COLLECTION_NAME = "suspicious"

DEFAULT_PCA_LIMIT = 1500
MAX_PCA_LIMIT = 5000
CHROMA_PAGE_SIZE = 1000
CHROMA_FETCH_CHUNK_SIZE = 200

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


def _load_chroma_settings() -> Dict[str, Any]:
    config_path = os.environ.get("SUSPICIOUS_SETTINGS_PATH", "/app/settings.json")
    try:
        with open(config_path, "r", encoding="utf-8") as fh:
            settings = json.load(fh)
        chromadb_conf = settings.get("chromadb", {}) if isinstance(settings, dict) else {}
        return {
            "host": chromadb_conf.get("host", DEFAULT_CHROMA_HOST),
            "port": chromadb_conf.get("port", DEFAULT_CHROMA_PORT),
            "collection_name": chromadb_conf.get(
                "collection_name",
                DEFAULT_CHROMA_COLLECTION_NAME,
            ),
        }
    except Exception as exc:
        logger.warning(
            "Unable to load suspicious settings from %s, using defaults: %s",
            config_path,
            exc,
        )
        return {
            "host": DEFAULT_CHROMA_HOST,
            "port": DEFAULT_CHROMA_PORT,
            "collection_name": DEFAULT_CHROMA_COLLECTION_NAME,
        }


CHROMA_SETTINGS = _load_chroma_settings()
CHROMA_HOST = CHROMA_SETTINGS["host"]
CHROMA_PORT = CHROMA_SETTINGS["port"]
CHROMA_COLLECTION_NAME = CHROMA_SETTINGS["collection_name"]


def _disable_chromadb_telemetry() -> None:
    try:
        os.environ.setdefault("CHROMADB_TELEMETRY_ENABLED", "false")
        os.environ.setdefault("ANONYMIZED_TELEMETRY", "false")
        os.environ.setdefault("CHROMADB_DISABLE_TELEMETRY", "true")
        os.environ.setdefault("CHROMADB_TELEMETRY", "false")
    except Exception:
        pass

    try:
        from chromadb.telemetry import telemetry as _telemetry  # type: ignore

        if hasattr(_telemetry, "TELEMETRY_ENABLED"):
            try:
                _telemetry.TELEMETRY_ENABLED = False  # type: ignore[attr-defined]
            except Exception:
                pass

        inst = getattr(_telemetry, "telemetry_instance", None)
        if inst is not None:
            for attr in ("capture", "capture_event", "capture_span", "flush"):
                if hasattr(inst, attr):
                    setattr(inst, attr, lambda *a, **k: None)
    except Exception:
        pass

    try:
        from chromadb.telemetry import product as _product  # type: ignore

        posthog_mod = getattr(_product, "posthog", None)
        if posthog_mod is not None:
            def _noop_capture(*args, **kwargs):
                return None

            if hasattr(posthog_mod, "capture"):
                posthog_mod.capture = _noop_capture  # type: ignore[assignment]
            client_cls = getattr(posthog_mod, "Posthog", None)
            if client_cls is not None and hasattr(client_cls, "capture"):
                client_cls.capture = _noop_capture  # type: ignore[assignment]
    except Exception:
        pass


def _get_chroma_collection(collection_name: str = CHROMA_COLLECTION_NAME):
    try:
        import chromadb
    except Exception as exc:
        logger.warning("ChromaDB not available in environment: %s", exc)
        return None

    _disable_chromadb_telemetry()

    try:
        client = chromadb.HttpClient(
            host=CHROMA_HOST,
            port=int(CHROMA_PORT),
        )
        return client.get_collection(name=collection_name)
    except Exception as exc:
        logger.error(
            "Failed to access ChromaDB collection %s on %s:%s: %s",
            collection_name,
            CHROMA_HOST,
            CHROMA_PORT,
            exc,
        )
        return None


def _validated_response(serializer_cls, payload: Dict[str, Any]) -> Response:
    serializer = serializer_cls(data=payload)
    serializer.is_valid(raise_exception=True)
    return Response(serializer.data)


def _empty_counts_payload() -> Dict[str, int]:
    return {
        CLASSIFICATION_SAFE: 0,
        CLASSIFICATION_UNWANTED: 0,
        CLASSIFICATION_DANGEROUS: 0,
    }


def _empty_pca_payload() -> Dict[str, Any]:
    return {
        "points": [],
        "explained_variance": [0.0, 0.0],
    }


def _empty_mail_volume_payload(days: Sequence[date]) -> Dict[str, Any]:
    return {
        "dates": list(days),
        "non_danger": [0] * len(days),
        "dangerous": [0] * len(days),
        "campaigns": [],
    }


def _coerce_list(value: Any) -> List[Any]:
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


def _coerce_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _normalize_classification(value: Any) -> str:
    text = str(value or "").strip().upper()
    if not text:
        return CLASSIFICATION_UNKNOWN
    return text


def _classification_bucket_for_counts(value: Any) -> Optional[str]:
    label = _normalize_classification(value)
    if label == CLASSIFICATION_SAFE:
        return CLASSIFICATION_SAFE
    if label in (CLASSIFICATION_UNWANTED, CLASSIFICATION_SUSPICIOUS):
        return CLASSIFICATION_UNWANTED
    if label == CLASSIFICATION_DANGEROUS:
        return CLASSIFICATION_DANGEROUS
    return None


def _stable_id_score(raw_id: str) -> int:
    digest = hashlib.blake2b(raw_id.encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(digest, byteorder="big", signed=False)


def _parse_source_refs(raw: Any) -> Tuple[str, ...]:
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


def _extract_headers_dict(raw: Any) -> Optional[Dict[str, Any]]:
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


def _parse_to_utc_datetime(value: Any) -> Optional[datetime]:
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


def _extract_sent_datetime(meta: Dict[str, Any]) -> Optional[datetime]:
    headers_dict = _extract_headers_dict(meta.get("headers"))
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
        parsed = _parse_to_utc_datetime(candidate)
        if parsed is not None:
            return parsed

    return None


def _extract_metadata_datetime(meta: Dict[str, Any]) -> Optional[datetime]:
    sent_dt = _extract_sent_datetime(meta)
    if sent_dt is not None:
        return sent_dt

    for key in DATE_METADATA_KEYS:
        value = meta.get(key)
        if not value:
            continue
        parsed = _parse_to_utc_datetime(value)
        if parsed is not None:
            return parsed

    for key, value in meta.items():
        if key in DATE_METADATA_KEYS or key == "headers":
            continue
        if not re.search(r"(date|time|timestamp|created|received|sent|submitted|ingested|ts)", str(key), re.IGNORECASE):
            continue
        parsed = _parse_to_utc_datetime(value)
        if parsed is not None:
            return parsed

    return None


def _extract_case_id(meta_obj: Any) -> Optional[str]:
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


def _iter_collection_pages(
    collection,
    *,
    include: Optional[List[str]] = None,
    page_size: int = CHROMA_PAGE_SIZE,
) -> Iterator[Dict[str, Any]]:
    offset = 0

    while True:
        kwargs: Dict[str, Any] = {
            "limit": page_size,
            "offset": offset,
        }
        if include is not None:
            kwargs["include"] = include

        try:
            page = collection.get(**kwargs)
        except TypeError:
            logger.warning(
                "Chroma collection.get() does not support paginated access with limit/offset; falling back to one-shot read."
            )
            fallback_kwargs: Dict[str, Any] = {}
            if include is not None:
                fallback_kwargs["include"] = include
            page = collection.get(**fallback_kwargs)
            if isinstance(page, dict):
                yield page
            return
        except Exception as exc:
            logger.error("Chroma paged read failed at offset %s: %s", offset, exc, exc_info=True)
            return

        if not isinstance(page, dict):
            logger.warning("Unexpected Chroma page type at offset %s: %r", offset, type(page))
            return

        ids = _coerce_list(page.get("ids"))
        if not ids:
            return

        yield page

        if len(ids) < page_size:
            return

        offset += len(ids)


def _iter_metadata_dicts(collection) -> Iterator[Dict[str, Any]]:
    for page in _iter_collection_pages(collection, include=["metadatas"]):
        metadatas = _coerce_list(page.get("metadatas"))
        for meta in metadatas:
            yield _coerce_dict(meta)


def _get_by_ids_resilient(
    collection,
    ids: Sequence[str],
    *,
    include: List[str],
    depth: int = 0,
) -> Dict[str, Any]:
    if not ids:
        return {"ids": [], "metadatas": [], "embeddings": []}

    try:
        return collection.get(ids=list(ids), include=include)
    except Exception as exc:
        if len(ids) == 1 or depth >= 8:
            logger.warning("Chroma get(ids=...) failed for %s ids: %s", len(ids), exc)
            return {"ids": [], "metadatas": [], "embeddings": []}

        mid = max(1, len(ids) // 2)
        left = _get_by_ids_resilient(collection, ids[:mid], include=include, depth=depth + 1)
        right = _get_by_ids_resilient(collection, ids[mid:], include=include, depth=depth + 1)

        return {
            "ids": _coerce_list(left.get("ids")) + _coerce_list(right.get("ids")),
            "metadatas": _coerce_list(left.get("metadatas")) + _coerce_list(right.get("metadatas")),
            "embeddings": _coerce_list(left.get("embeddings")) + _coerce_list(right.get("embeddings")),
        }


def _fetch_records_for_ids(
    collection,
    ids: Sequence[str],
) -> List[Tuple[str, Optional[Any], Dict[str, Any]]]:
    records: List[Tuple[str, Optional[Any], Dict[str, Any]]] = []

    for start in range(0, len(ids), CHROMA_FETCH_CHUNK_SIZE):
        chunk_ids = list(ids[start:start + CHROMA_FETCH_CHUNK_SIZE])
        res = _get_by_ids_resilient(
            collection,
            chunk_ids,
            include=["embeddings", "metadatas"],
        )
        returned_ids = [str(x) for x in _coerce_list(res.get("ids"))]
        returned_embeddings = _coerce_list(res.get("embeddings"))
        returned_metadatas = _coerce_list(res.get("metadatas"))

        by_id: Dict[str, Tuple[Optional[Any], Dict[str, Any]]] = {}
        for idx, row_id in enumerate(returned_ids):
            embedding = returned_embeddings[idx] if idx < len(returned_embeddings) else None
            metadata = _coerce_dict(returned_metadatas[idx] if idx < len(returned_metadatas) else {})
            by_id[row_id] = (embedding, metadata)

        for row_id in chunk_ids:
            embedding, metadata = by_id.get(row_id, (None, {}))
            records.append((row_id, embedding, metadata))

    return records


def _select_deterministic_sample_ids(collection, sample_size: int) -> List[str]:
    if sample_size <= 0:
        return []

    heap: List[Tuple[int, str]] = []

    for page in _iter_collection_pages(collection, include=[]):
        for raw_id in _coerce_list(page.get("ids")):
            row_id = str(raw_id)
            score = _stable_id_score(row_id)
            entry = (-score, row_id)

            if len(heap) < sample_size:
                heapq.heappush(heap, entry)
                continue

            current_worst_score = -heap[0][0]
            if score < current_worst_score:
                heapq.heapreplace(heap, entry)

    selected = [(-neg_score, row_id) for neg_score, row_id in heap]
    selected.sort(key=lambda item: (item[0], item[1]))
    return [row_id for _, row_id in selected]


def _format_campaign_name(source_refs: Tuple[str, ...], fallback_index: int) -> str:
    if not source_refs:
        return f"Campaign {fallback_index}"
    if len(source_refs) <= 3:
        return ", ".join(source_refs)
    return ", ".join(source_refs[:3]) + "…"


@extend_schema(
    tags=["Campaigns"],
)
class CampaignClassificationCountsView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        operation_id="campaign_classification_counts",
        summary="Get campaign classification counts",
        description=(
            "Return aggregate message counts by top-level classification for the current "
            "Chroma collection.\n\n"
            "**Label semantics**\n"
            "- `SAFE`: benign content.\n"
            "- `UNWANTED`: unwanted but not dangerous content.\n"
            "- `DANGEROUS`: confirmed dangerous content.\n\n"
            "**Aggregation rule**\n"
            "- Records labeled `SUSPICIOUS` are folded into `UNWANTED` for this endpoint.\n"
            "- This is intentional to preserve the existing frontend contract, which expects "
            "three buckets only: `SAFE`, `UNWANTED`, and `DANGEROUS`.\n\n"
            "**Implementation note**\n"
            "- Counts are computed by scanning metadata and normalizing the `classification` "
            "field rather than issuing multiple per-label queries."
        ),
        responses={
            200: OpenApiResponse(
                response=CampaignClassificationCountsSerializer,
                description=(
                    "Three-bucket classification counts. `SUSPICIOUS` is aggregated into "
                    "`UNWANTED`."
                ),
            ),
        },
        examples=[
            OpenApiExample(
                "Classification counts",
                value={
                    "SAFE": 128,
                    "UNWANTED": 41,
                    "DANGEROUS": 9,
                },
                response_only=True,
            ),
        ],
    )
    def get(self, request):
        collection = _get_chroma_collection()
        if collection is None:
            return _validated_response(
                CampaignClassificationCountsSerializer,
                _empty_counts_payload(),
            )

        counts = _empty_counts_payload()
        scanned = 0

        try:
            for meta in _iter_metadata_dicts(collection):
                scanned += 1
                bucket = _classification_bucket_for_counts(meta.get("classification"))
                if bucket is not None:
                    counts[bucket] += 1

            logger.debug(
                "Campaign classification counts computed from %s metadata rows.",
                scanned,
            )
        except Exception as exc:
            logger.error("Error computing campaign classification counts: %s", exc, exc_info=True)
            counts = _empty_counts_payload()

        return _validated_response(CampaignClassificationCountsSerializer, counts)


@extend_schema(
    tags=["Campaigns"],
)
class CampaignPcaView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        operation_id="campaign_pca",
        summary="Get a 2D PCA projection of sampled embeddings",
        description=(
            "Return a two-dimensional PCA projection of a deterministic sample of embeddings "
            "from the current Chroma collection.\n\n"
            "**Label semantics**\n"
            "- Point `label` is the normalized uppercase value of the metadata "
            "`classification` field.\n"
            "- Unlike the counts endpoint, this endpoint does **not** fold `SUSPICIOUS` into "
            "`UNWANTED`; labels are exposed as stored after normalization.\n\n"
            "**Sampling behavior**\n"
            "- The endpoint does **not** fetch all embeddings first.\n"
            "- It first walks collection IDs, then selects a deterministic subset up to `limit` "
            "using a stable hash of the Chroma record ID.\n"
            "- The same collection contents and `limit` produce the same sample order.\n"
            "- After sampling, embeddings are grouped by vector dimensionality and PCA is run "
            "only on the largest dimension bucket to avoid mixing incompatible embeddings.\n\n"
            "**Numerical behavior**\n"
            "- PCA is computed with centered vectors and SVD in float64.\n"
            "- `explained_variance` contains the variance ratios for PC1 and PC2.\n"
            "- If only one usable dimension exists, PC2 is returned as zero."
        ),
        parameters=[
            OpenApiParameter(
                name="limit",
                type=int,
                location=OpenApiParameter.QUERY,
                required=False,
                description=(
                    "Maximum number of records to sample before PCA. "
                    f"Default: {DEFAULT_PCA_LIMIT}. Maximum: {MAX_PCA_LIMIT}."
                ),
            ),
        ],
        responses={
            200: OpenApiResponse(
                response=CampaignPcaResponseSerializer,
                description="PCA projection points and explained variance ratios for PC1 and PC2.",
            ),
        },
        examples=[
            OpenApiExample(
                "PCA response",
                value={
                    "explained_variance": [0.37, 0.18],
                    "points": [
                        {
                            "x": -2.14,
                            "y": 0.88,
                            "label": "SAFE",
                            "suspicious_case_id": "1234",
                            "sourceRefs": ["sender-domain-a", "subject-cluster-1"],
                        },
                        {
                            "x": 1.27,
                            "y": -0.42,
                            "label": "SUSPICIOUS",
                            "suspicious_case_id": "1250",
                            "sourceRefs": ["sender-domain-b"],
                        },
                    ],
                },
                response_only=True,
            ),
        ],
    )
    def get(self, request):
        params = CampaignPcaQuerySerializer(data=request.query_params)
        params.is_valid(raise_exception=True)
        limit = int(params.validated_data.get("limit", DEFAULT_PCA_LIMIT))

        collection = _get_chroma_collection()
        if collection is None:
            return _validated_response(CampaignPcaResponseSerializer, _empty_pca_payload())

        try:
            sampled_ids = _select_deterministic_sample_ids(collection, min(limit, MAX_PCA_LIMIT))
            if not sampled_ids:
                return _validated_response(CampaignPcaResponseSerializer, _empty_pca_payload())

            records = _fetch_records_for_ids(collection, sampled_ids)

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

                dim_buckets.setdefault(int(vector.size), []).append(
                    (row_id, vector, metadata)
                )

            if not dim_buckets:
                logger.warning(
                    "PCA sampling yielded no valid embeddings. sampled_ids=%s skipped_empty=%s skipped_invalid=%s",
                    len(sampled_ids),
                    skipped_empty,
                    skipped_invalid,
                )
                return _validated_response(CampaignPcaResponseSerializer, _empty_pca_payload())

            chosen_dim = max(dim_buckets.keys(), key=lambda dim: (len(dim_buckets[dim]), dim))
            selected = dim_buckets[chosen_dim]
            selected.sort(key=lambda item: _stable_id_score(item[0]))

            vectors = [item[1] for item in selected]
            metas = [item[2] for item in selected]

            if len(vectors) == 1:
                meta = metas[0]
                payload = {
                    "points": [{
                        "x": 0.0,
                        "y": 0.0,
                        "label": _normalize_classification(meta.get("classification")),
                        "suspicious_case_id": _extract_case_id(meta),
                        "sourceRefs": list(_parse_source_refs(meta.get("sourceRefs"))),
                    }],
                    "explained_variance": [0.0, 0.0],
                }
                return _validated_response(CampaignPcaResponseSerializer, payload)

            X = np.stack(vectors, axis=0)
            X_centered = X - X.mean(axis=0, keepdims=True)

            if X_centered.shape[1] == 1:
                xs = X_centered[:, 0]
                ys = np.zeros_like(xs)
                denom = float(np.sum(np.square(xs)))
                ratios = [1.0 if denom > 0.0 else 0.0, 0.0]
            else:
                try:
                    _, singular_values, vt = np.linalg.svd(X_centered, full_matrices=False)
                except Exception as exc:
                    logger.error("PCA SVD failed: %s", exc, exc_info=True)
                    return _validated_response(CampaignPcaResponseSerializer, _empty_pca_payload())

                components = vt[:2]
                scores = X_centered @ components.T
                xs = scores[:, 0]
                ys = scores[:, 1] if scores.shape[1] > 1 else np.zeros(X_centered.shape[0])

                eigenvalue_numerators = np.square(singular_values)
                denom = float(eigenvalue_numerators.sum()) if eigenvalue_numerators.size else 0.0
                if denom > 0.0:
                    ratios = [
                        float(eigenvalue_numerators[0] / denom),
                        float(eigenvalue_numerators[1] / denom) if eigenvalue_numerators.size > 1 else 0.0,
                    ]
                else:
                    ratios = [0.0, 0.0]

            points = []
            for idx, meta in enumerate(metas):
                points.append({
                    "x": float(xs[idx]),
                    "y": float(ys[idx]),
                    "label": _normalize_classification(meta.get("classification")),
                    "suspicious_case_id": _extract_case_id(meta),
                    "sourceRefs": list(_parse_source_refs(meta.get("sourceRefs"))),
                })

            logger.debug(
                "Campaign PCA computed. requested_limit=%s sampled_ids=%s valid_vectors=%s chosen_dim=%s",
                limit,
                len(sampled_ids),
                len(vectors),
                chosen_dim,
            )

            payload = {
                "points": points,
                "explained_variance": ratios,
            }
            return _validated_response(CampaignPcaResponseSerializer, payload)

        except Exception as exc:
            logger.error("Error computing PCA points: %s", exc, exc_info=True)
            return _validated_response(CampaignPcaResponseSerializer, _empty_pca_payload())


@extend_schema(
    tags=["Campaigns"],
)
class CampaignMailVolumeView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        operation_id="campaign_mail_volume",
        summary="Get mail volume for the last 15 days with inferred campaign windows",
        description=(
            "Return daily mail volume for the last 15 UTC days and inferred campaign date bands.\n\n"
            "**Label semantics**\n"
            "- `dangerous` counts only records whose normalized `classification` is `DANGEROUS`.\n"
            "- `non_danger` counts every other classified or unclassified record that has a usable date.\n\n"
            "**Date extraction behavior**\n"
            "- The endpoint prefers parsed mail headers such as `Date` when available.\n"
            "- It then falls back to known metadata timestamp fields such as `sent_date`, `date`, "
            "`received_at`, `created_at`, `timestamp`, and related keys.\n"
            "- All date bucketing is performed in UTC.\n\n"
            "**Campaign grouping heuristic**\n"
            "- Campaign bands are inferred by grouping records that share the same normalized "
            "`sourceRefs` set.\n"
            "- `sourceRefs` are parsed defensively from arrays or string-encoded lists, de-duplicated, "
            "sorted, and then used as the grouping key.\n"
            "- This is a heuristic, not a guaranteed campaign identifier. Reused or noisy "
            "`sourceRefs` may merge unrelated messages into the same displayed band."
        ),
        responses={
            200: OpenApiResponse(
                response=CampaignMailVolumeResponseSerializer,
                description=(
                    "Daily UTC mail volume and campaign date bands inferred from shared `sourceRefs`."
                ),
            ),
        },
        examples=[
            OpenApiExample(
                "Mail volume response",
                value={
                    "dates": [
                        "2026-03-02",
                        "2026-03-03",
                        "2026-03-04",
                    ],
                    "non_danger": [4, 7, 3],
                    "dangerous": [1, 0, 2],
                    "campaigns": [
                        {
                            "name": "sender-domain-a, subject-cluster-1",
                            "start": "2026-03-02T00:00:00Z",
                            "end": "2026-03-04T23:59:59.999999Z",
                        }
                    ],
                },
                response_only=True,
            ),
        ],
    )
    def get(self, request):
        today_utc = datetime.now(dt_timezone.utc).date()
        start_utc = today_utc - timedelta(days=14)
        all_days = [start_utc + timedelta(days=i) for i in range(15)]
        day_index = {day: idx for idx, day in enumerate(all_days)}

        collection = _get_chroma_collection()
        if collection is None:
            return _validated_response(
                CampaignMailVolumeResponseSerializer,
                _empty_mail_volume_payload(all_days),
            )

        non_danger = [0] * len(all_days)
        dangerous = [0] * len(all_days)
        campaign_windows: Dict[Tuple[str, ...], Dict[str, datetime]] = {}

        scanned = 0
        skipped_no_date = 0

        try:
            for meta in _iter_metadata_dicts(collection):
                scanned += 1
                meta = _coerce_dict(meta)

                sent_dt = _extract_metadata_datetime(meta)
                if sent_dt is None:
                    skipped_no_date += 1
                    continue

                sent_dt = sent_dt.astimezone(dt_timezone.utc)
                day = sent_dt.date()

                source_refs = _parse_source_refs(meta.get("sourceRefs"))
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

                classification = _normalize_classification(meta.get("classification"))
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
            return _validated_response(
                CampaignMailVolumeResponseSerializer,
                _empty_mail_volume_payload(all_days),
            )

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
                "name": _format_campaign_name(source_refs, idx_num),
                "start": clamped_start,
                "end": clamped_end,
            })

        payload = {
            "dates": all_days,
            "non_danger": non_danger,
            "dangerous": dangerous,
            "campaigns": campaigns_out,
        }
        return _validated_response(CampaignMailVolumeResponseSerializer, payload)