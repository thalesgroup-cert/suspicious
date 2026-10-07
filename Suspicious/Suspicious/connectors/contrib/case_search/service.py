"""Elasticsearch index of cases: document builder, index management, search.

The ``elasticsearch`` client is imported lazily so the app (and the test suite)
load without it installed."""
from __future__ import annotations

import logging

from cortex_job.cortex_utils.case_targets import collect_case_targets

logger = logging.getLogger("connectors.contrib.case_search")

DEFAULT_URL = "http://elasticsearch:9200"
DEFAULT_INDEX = "suspicious-cases"
DEFAULT_TIMEOUT = 2.0      # search path: the user is waiting
INDEX_TIMEOUT = 10.0       # event/backfill path: a Celery worker is waiting
MIN_QUERY, MAX_QUERY = 3, 20
MAX_IDS = 10_000
MAX_VALUE_CHARS = 512
TEXT_FIELDS = ("description", "reporter", "mail_subject", "file_name", "observables")

# select_related set that makes build_document() cheap on a Case queryset.
CASE_RELATED = (
    "reporter", "fileOrMail", "fileOrMail__mail", "fileOrMail__file",
    "nonFileIocs", "nonFileIocs__url", "nonFileIocs__ip", "nonFileIocs__hash",
    "observable_group",
)


def get_client(config: dict, timeout: float):
    from elasticsearch import Elasticsearch

    return Elasticsearch(config.get("url") or DEFAULT_URL, request_timeout=timeout)


def index_body() -> dict:
    text = {"type": "text", "analyzer": "substr_index", "search_analyzer": "substr_search"}
    return {
        "settings": {
            "index": {
                "max_ngram_diff": MAX_QUERY - MIN_QUERY,
                "number_of_shards": 1,
                "number_of_replicas": 0,  # single-node cluster; replicas would stay unassigned
            },
            "analysis": {
                "tokenizer": {
                    "substr_ngram": {"type": "ngram", "min_gram": MIN_QUERY, "max_gram": MAX_QUERY},
                },
                "analyzer": {
                    "substr_index": {
                        "type": "custom", "tokenizer": "substr_ngram", "filter": ["lowercase"],
                    },
                    # Whole query is one term, matched literally against the ngrams.
                    "substr_search": {
                        "type": "custom", "tokenizer": "keyword", "filter": ["lowercase"],
                    },
                },
            },
        },
        "mappings": {"properties": {name: dict(text) for name in TEXT_FIELDS}},
    }


def ensure_index(client, index: str) -> None:
    if client.indices.exists(index=index):
        return
    body = index_body()
    # ignore_status=400: another worker created it between exists() and create().
    client.options(ignore_status=400).indices.create(
        index=index, settings=body["settings"], mappings=body["mappings"],
    )


def _value(instance, data_type: str) -> str | None:
    if data_type == "file":
        return instance.file_path.name
    if data_type in ("url", "ip", "mail"):
        return instance.address
    if data_type in ("hash", "domain"):
        return instance.value
    return None  # mail_body / mail_header: nothing searchable


def build_document(case) -> dict:
    mail = getattr(case.fileOrMail, "mail", None) if case.fileOrMail_id else None
    doc = {
        "description": case.description or "",
        "reporter": f"{case.reporter.email} {case.reporter.username}",
        "mail_subject": mail.subject if mail else "",
        "file_name": [],
        "observables": [],
    }
    for instance, data_type in collect_case_targets(case):
        value = _value(instance, data_type)
        if value:
            key = "file_name" if data_type == "file" else "observables"
            doc[key].append(value[:MAX_VALUE_CHARS])
    return doc


def index_case(client, index: str, case) -> None:
    client.index(index=index, id=case.pk, document=build_document(case))


def bulk_index(client, index: str, cases) -> tuple[int, int]:
    from elasticsearch import helpers

    actions = (
        {"_index": index, "_id": case.pk, "_source": build_document(case)} for case in cases
    )
    ok, errors = helpers.bulk(client, actions, chunk_size=500, raise_on_error=False)
    return ok, len(errors)


def search_ids(client, index: str, query: str) -> list[int]:
    resp = client.search(
        index=index,
        query={"multi_match": {"query": query, "fields": list(TEXT_FIELDS)}},
        source=False,
        size=MAX_IDS,
        track_total_hits=False,
    )
    return [int(hit["_id"]) for hit in resp["hits"]["hits"]]


def search_case_ids(query: str | None) -> list[int] | None:
    """Case ids matching ``query`` according to ES, or ``None`` meaning "use the
    ORM search" (connector off, query length outside 3-20, any ES failure)."""
    q = (query or "").strip()
    if not MIN_QUERY <= len(q) <= MAX_QUERY:
        return None
    try:
        from connectors.delivery import get_state
        from connectors.registry import registry

        if not get_state("case_search").enabled:
            return None
        config = registry.instantiate("case_search").config
        client = get_client(config, timeout=float(config.get("timeout_seconds") or DEFAULT_TIMEOUT))
        return search_ids(client, config.get("index") or DEFAULT_INDEX, q)
    except Exception:  # noqa: BLE001 — search must degrade, never fail
        logger.warning("ES case search failed; falling back to ORM search", exc_info=True)
        return None
