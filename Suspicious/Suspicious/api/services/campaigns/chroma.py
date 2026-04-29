"""
ChromaDB connection, telemetry suppression, and paginated iteration helpers.
"""
import hashlib
import json
import logging
import os
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

from .metadata import coerce_dict, coerce_list

logger = logging.getLogger(__name__)

DEFAULT_CHROMA_HOST = "chromadb"
DEFAULT_CHROMA_PORT = 8000
DEFAULT_CHROMA_COLLECTION_NAME = "suspicious"

CHROMA_PAGE_SIZE = 1000
CHROMA_FETCH_CHUNK_SIZE = 200


def _load_chroma_settings() -> Dict[str, Any]:
    config_path = os.environ.get("SUSPICIOUS_SETTINGS_PATH", "/app/settings.json")
    try:
        with open(config_path, "r", encoding="utf-8") as fh:
            settings = json.load(fh)

        if not isinstance(settings, dict):
            raise ValueError("Invalid settings format")

        chromadb_conf = (
            settings
            .get("integrations", {})
            .get("chromadb", {})
        )

        return {
            "host": str(chromadb_conf.get("host", DEFAULT_CHROMA_HOST)),
            "port": int(chromadb_conf.get("port", DEFAULT_CHROMA_PORT)),
            "collection_name": str(
                chromadb_conf.get("collection_name", DEFAULT_CHROMA_COLLECTION_NAME)
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


def get_chroma_collection(collection_name: str = CHROMA_COLLECTION_NAME):
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


def stable_id_score(raw_id: str) -> int:
    digest = hashlib.blake2b(raw_id.encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(digest, byteorder="big", signed=False)


def iter_collection_pages(
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

        ids = coerce_list(page.get("ids"))
        if not ids:
            return

        yield page

        if len(ids) < page_size:
            return

        offset += len(ids)


def iter_metadata_dicts(collection) -> Iterator[Dict[str, Any]]:
    for page in iter_collection_pages(collection, include=["metadatas"]):
        metadatas = coerce_list(page.get("metadatas"))
        for meta in metadatas:
            yield coerce_dict(meta)


def get_by_ids_resilient(
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
        left = get_by_ids_resilient(collection, ids[:mid], include=include, depth=depth + 1)
        right = get_by_ids_resilient(collection, ids[mid:], include=include, depth=depth + 1)

        return {
            "ids": coerce_list(left.get("ids")) + coerce_list(right.get("ids")),
            "metadatas": coerce_list(left.get("metadatas")) + coerce_list(right.get("metadatas")),
            "embeddings": coerce_list(left.get("embeddings")) + coerce_list(right.get("embeddings")),
        }


def fetch_records_for_ids(
    collection,
    ids: Sequence[str],
) -> List[Tuple[str, Optional[Any], Dict[str, Any]]]:
    records: List[Tuple[str, Optional[Any], Dict[str, Any]]] = []

    for start in range(0, len(ids), CHROMA_FETCH_CHUNK_SIZE):
        chunk_ids = list(ids[start:start + CHROMA_FETCH_CHUNK_SIZE])
        res = get_by_ids_resilient(
            collection,
            chunk_ids,
            include=["embeddings", "metadatas"],
        )
        returned_ids = [str(x) for x in coerce_list(res.get("ids"))]
        returned_embeddings = coerce_list(res.get("embeddings"))
        returned_metadatas = coerce_list(res.get("metadatas"))

        by_id: Dict[str, Tuple[Optional[Any], Dict[str, Any]]] = {}
        for idx, row_id in enumerate(returned_ids):
            embedding = returned_embeddings[idx] if idx < len(returned_embeddings) else None
            metadata = coerce_dict(returned_metadatas[idx] if idx < len(returned_metadatas) else {})
            by_id[row_id] = (embedding, metadata)

        for row_id in chunk_ids:
            embedding, metadata = by_id.get(row_id, (None, {}))
            records.append((row_id, embedding, metadata))

    return records


def select_deterministic_sample_ids(collection, sample_size: int) -> List[str]:
    import heapq

    if sample_size <= 0:
        return []

    heap: List[Tuple[int, str]] = []

    for page in iter_collection_pages(collection, include=[]):
        for raw_id in coerce_list(page.get("ids")):
            row_id = str(raw_id)
            score = stable_id_score(row_id)
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
