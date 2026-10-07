# Case search through Elasticsearch Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Answer the investigations search box from an Elasticsearch index of cases, falling back to today's ORM search whenever ES is unavailable.

**Architecture:** A new built-in connector `case_search` keeps a `suspicious-cases` index current from the `case_created`, `case_modified` and `case_finalised` events. `InvestigationAccessMixin.filter_case_queryset` asks `search_case_ids()` for matching ids and applies `pk__in`; every other filter, scoping, ordering and pagination stay in the ORM. `search_case_ids()` returns `None` for "use the ORM" (connector disabled, query too short/long, any ES error).

**Tech Stack:** Django 6.1, Celery connector framework (`connectors/`), `elasticsearch` Python client 8.x, MariaDB, Elasticsearch 8.19 (existing single-node service).

**Spec:** `docs/specs/2026-10-07-case-search-elasticsearch-design.md`

## Global Constraints

- Index name `suspicious-cases`, one document per case, document id = case pk.
- Substring match via ngram analyzer min 3 / max 20; queries outside 3–20 characters use the ORM path.
- ES search timeout 2 s, result cap 10 000 ids.
- Connector ships `enabled_by_default=False`.
- Any ES failure on the search path falls back to the ORM search; never raise to the user.
- Config lives in the connector section `integrations.case_search` (`url`, `index`, `timeout_seconds`); defaults `http://elasticsearch:9200`, `suspicious-cases`, `2`.
- Dependency: `elasticsearch>=8.19,<9` in `Suspicious/requirements.txt`. Import the client lazily so the app and tests load without it.
- Tests run on SQLite via `ww test backend <labels>`; ES is mocked. Remove the stray `Suspicious/Suspicious/gunicorn.conf.py` before committing.
- Commit with explicit `git add <paths>`; Conventional Commits; end messages with `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`.
- Paths below are relative to `Suspicious/Suspicious/` unless they start with `docs/` or `deployment/`.

## Review Focus

- Query with regex/wildcard characters (`*`, `\`, `"`, `(`): must be matched literally by the keyword search analyzer, not parsed. Test in Task 1.
- Search returns no hits (`[]`): the view must return an empty page, not fall back to everything. Test in Task 2.
- Numeric search (`123`): case id match must still work alongside ES ids. Test in Task 2.
- Enabled before `reindex_cases` ran (index missing): `NotFoundError` must fall back to the ORM. Test in Task 1.
- Very long URL/subject values: truncated to 512 characters so the ngram field stays bounded. Test in Task 1.

---

### Task 1: Connector, document builder and search helper

**Files:**
- Create: `connectors/contrib/case_search/__init__.py` (empty)
- Create: `connectors/contrib/case_search/service.py`
- Create: `connectors/contrib/case_search/connector.py`
- Create: `connectors/contrib/case_search/tests/__init__.py` (empty)
- Create: `connectors/contrib/case_search/tests/test_service.py`
- Create: `connectors/contrib/case_search/tests/test_connector.py`
- Modify: `connectors/contrib/__init__.py` (add to `BUILTIN_CONNECTOR_PATHS`)
- Modify: `requirements.txt` (add `elasticsearch>=8.19,<9`)

**Interfaces:**
- Produces (`service.py`):
  - constants `DEFAULT_URL`, `DEFAULT_INDEX`, `DEFAULT_TIMEOUT`, `INDEX_TIMEOUT`, `MIN_QUERY=3`, `MAX_QUERY=20`, `MAX_IDS=10_000`, `TEXT_FIELDS`, `CASE_RELATED`
  - `get_client(config: dict, timeout: float)` -> `Elasticsearch`
  - `index_body() -> dict` (keys `settings`, `mappings`)
  - `ensure_index(client, index: str) -> None`
  - `build_document(case) -> dict`
  - `index_case(client, index, case) -> None`
  - `bulk_index(client, index, cases) -> tuple[int, int]` (ok count, error count)
  - `search_ids(client, index, query) -> list[int]`
  - `search_case_ids(query: str) -> list[int] | None`
- Produces (`connector.py`): `CaseSearchConnector` with manifest name `case_search`.

- [ ] **Step 1: Write the failing tests**

`connectors/contrib/case_search/tests/test_service.py`:

```python
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from case_handler.models import Case, CaseHasNonFileIocs
from connectors.contrib.case_search import service
from mail_feeder.models import Mail
from case_handler.models import CaseHasFileOrMail
from url_process.models import URL


def _case(user, **kw):
    return Case.objects.create(description=kw.pop("description", "d"), reporter=user, **kw)


class BuildDocumentTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("alice", "alice@x.io", "pw")

    def test_url_ioc_and_reporter_and_description(self):
        case = _case(self.user, description="invoice phish")
        url = URL.objects.create(address="http://evil.test/login")
        assoc = CaseHasNonFileIocs.objects.create(case=case, url=url)
        case.nonFileIocs = assoc
        case.save()
        case = Case.objects.select_related(*service.CASE_RELATED).get(pk=case.pk)

        doc = service.build_document(case)

        self.assertEqual(doc["description"], "invoice phish")
        self.assertIn("alice@x.io", doc["reporter"])
        self.assertIn("alice", doc["reporter"])
        self.assertEqual(doc["observables"], ["http://evil.test/login"])
        self.assertEqual(doc["mail_subject"], "")

    def test_mail_subject(self):
        case = _case(self.user)
        mail = Mail.objects.create(
            subject="Your invoice", reportedBy="r", date=timezone.now(), to="t", mail_id="m1",
        )
        case.fileOrMail = CaseHasFileOrMail.objects.create(case=case, mail=mail)
        case.save()
        case = Case.objects.select_related(*service.CASE_RELATED).get(pk=case.pk)

        self.assertEqual(service.build_document(case)["mail_subject"], "Your invoice")

    def test_long_values_are_truncated(self):
        case = _case(self.user)
        url = URL.objects.create(address="http://x.test/" + "a" * 5000)
        case.nonFileIocs = CaseHasNonFileIocs.objects.create(case=case, url=url)
        case.save()
        case = Case.objects.select_related(*service.CASE_RELATED).get(pk=case.pk)

        self.assertEqual(len(service.build_document(case)["observables"][0]), 512)


class SearchCaseIdsTests(TestCase):
    def _enabled(self, enabled=True):
        return mock.patch(
            "connectors.delivery.get_state", return_value=mock.Mock(enabled=enabled)
        )

    def test_out_of_range_queries_skip_es(self):
        with mock.patch.object(service, "get_client") as gc:
            self.assertIsNone(service.search_case_ids("ab"))
            self.assertIsNone(service.search_case_ids("x" * 21))
            self.assertIsNone(service.search_case_ids(None))
            gc.assert_not_called()

    def test_disabled_connector_returns_none(self):
        with self._enabled(False), mock.patch.object(service, "get_client") as gc:
            self.assertIsNone(service.search_case_ids("evil.test"))
            gc.assert_not_called()

    def test_returns_ids_from_hits(self):
        client = mock.Mock()
        client.search.return_value = {"hits": {"hits": [{"_id": "7"}, {"_id": "3"}]}}
        with self._enabled(), mock.patch.object(service, "get_client", return_value=client):
            self.assertEqual(service.search_case_ids("evil.test"), [7, 3])

    def test_no_hits_returns_empty_list_not_none(self):
        client = mock.Mock()
        client.search.return_value = {"hits": {"hits": []}}
        with self._enabled(), mock.patch.object(service, "get_client", return_value=client):
            self.assertEqual(service.search_case_ids("evil.test"), [])

    def test_wildcard_characters_are_sent_as_a_plain_match(self):
        client = mock.Mock()
        client.search.return_value = {"hits": {"hits": []}}
        with self._enabled(), mock.patch.object(service, "get_client", return_value=client):
            service.search_case_ids('a*b"(c')
        query = client.search.call_args.kwargs["query"]
        self.assertEqual(query["multi_match"]["query"], 'a*b"(c')

    def test_any_error_falls_back_to_none(self):
        client = mock.Mock()
        client.search.side_effect = RuntimeError("index_not_found")
        with self._enabled(), mock.patch.object(service, "get_client", return_value=client):
            self.assertIsNone(service.search_case_ids("evil.test"))
```

`connectors/contrib/case_search/tests/test_connector.py`:

```python
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase

from case_handler.models import Case
from connectors.base import CaseEvent
from connectors.contrib.case_search import service
from connectors.contrib.case_search.connector import CaseSearchConnector


def _event(case_id):
    return CaseEvent(
        event="case_created", case_id=case_id, status="To Do", results="Inconclusive",
        final_score=0, confidence=0, reporter_email="a@x.io", created_at="2026-10-07T00:00:00",
    )


class CaseSearchConnectorTests(TestCase):
    def test_manifest(self):
        m = CaseSearchConnector.manifest
        m.validate()
        self.assertFalse(m.enabled_by_default)
        self.assertEqual(
            set(m.events), {"case_created", "case_modified", "case_finalised"}
        )

    def test_events_index_the_case(self):
        user = User.objects.create_user("alice", "alice@x.io", "pw")
        case = Case.objects.create(description="hello", reporter=user)
        client = mock.Mock()
        client.indices.exists.return_value = True
        with mock.patch.object(service, "get_client", return_value=client):
            conn = CaseSearchConnector({"index": "idx-test"})
            conn.on_case_created(_event(case.pk))
            conn.on_case_modified(_event(case.pk))
            conn.on_case_finalised(_event(case.pk))
        self.assertEqual(client.index.call_count, 3)
        kwargs = client.index.call_args.kwargs
        self.assertEqual(kwargs["index"], "idx-test")
        self.assertEqual(kwargs["id"], case.pk)
        self.assertEqual(kwargs["document"]["description"], "hello")

    def test_missing_case_is_ignored(self):
        client = mock.Mock()
        with mock.patch.object(service, "get_client", return_value=client):
            CaseSearchConnector({}).on_case_created(_event(999999))
        client.index.assert_not_called()

    def test_es_failure_raises_so_framework_retries(self):
        user = User.objects.create_user("bob", "b@x.io", "pw")
        case = Case.objects.create(description="x", reporter=user)
        client = mock.Mock()
        client.indices.exists.return_value = True
        client.index.side_effect = RuntimeError("es down")
        with mock.patch.object(service, "get_client", return_value=client):
            with self.assertRaises(RuntimeError):
                CaseSearchConnector({}).on_case_created(_event(case.pk))

    def test_health_check_never_raises(self):
        with mock.patch.object(service, "get_client", side_effect=RuntimeError("boom")):
            self.assertFalse(CaseSearchConnector({}).health_check().ok)
        client = mock.Mock()
        client.cluster.health.return_value = {"status": "yellow"}
        with mock.patch.object(service, "get_client", return_value=client):
            self.assertTrue(CaseSearchConnector({}).health_check().ok)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `ww test backend connectors.contrib.case_search`
Expected: FAIL/ERROR with `ModuleNotFoundError: connectors.contrib.case_search.service`.

- [ ] **Step 3: Write the implementation**

`connectors/contrib/case_search/service.py`:

```python
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
```

`connectors/contrib/case_search/connector.py`:

```python
"""Keeps the ``suspicious-cases`` Elasticsearch index current so the
investigations search box can query it instead of scanning SQL tables."""
from __future__ import annotations

from case_handler.models import Case
from connectors.base import (
    EVENT_CASE_CREATED,
    EVENT_CASE_FINALISED,
    EVENT_CASE_MODIFIED,
    ConfigField,
    Connector,
    ConnectorManifest,
    HealthStatus,
)
from connectors.contrib.case_search import service


class CaseSearchConnector(Connector):
    manifest = ConnectorManifest(
        name="case_search",
        version="1.0.0",
        author="Thales CERT",
        category="Search",
        description="Index cases in Elasticsearch for fast investigation search. "
                    "Run `manage.py reindex_cases` before enabling.",
        config_schema=(
            ConfigField("url", "url", default=service.DEFAULT_URL, help="Elasticsearch URL"),
            ConfigField("index", "str", default=service.DEFAULT_INDEX, help="Index name"),
            ConfigField("timeout_seconds", "int", default=2, help="Search timeout"),
        ),
        events=(EVENT_CASE_CREATED, EVENT_CASE_MODIFIED, EVENT_CASE_FINALISED),
        enabled_by_default=False,
    )

    @property
    def index(self) -> str:
        return self.config.get("index") or service.DEFAULT_INDEX

    def health_check(self) -> HealthStatus:
        try:
            client = service.get_client(self.config, timeout=service.INDEX_TIMEOUT)
            status = client.cluster.health()["status"]
            return HealthStatus(ok=status in ("green", "yellow"), detail=f"cluster {status}")
        except Exception as exc:  # noqa: BLE001 — health check must not raise
            return HealthStatus(ok=False, detail=str(exc))

    def _index_case(self, event) -> None:
        try:
            case = Case.objects.select_related(*service.CASE_RELATED).get(pk=event.case_id)
        except Case.DoesNotExist:
            return
        client = service.get_client(self.config, timeout=service.INDEX_TIMEOUT)
        service.ensure_index(client, self.index)
        service.index_case(client, self.index, case)  # raises on failure: framework retries

    def on_case_created(self, event) -> None:
        self._index_case(event)

    def on_case_modified(self, event) -> None:
        self._index_case(event)

    def on_case_finalised(self, event) -> None:
        self._index_case(event)
```

`connectors/contrib/__init__.py` — add the line after the `ai_narration` entry:

```python
    "connectors.contrib.case_search.connector:CaseSearchConnector",
```

`requirements.txt` — add next to `chromadb==1.5.9`:

```
elasticsearch>=8.19,<9
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `ww test backend connectors`
Expected: PASS (new tests plus the existing connectors suite; registry loads the new connector).

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/connectors/contrib/case_search Suspicious/Suspicious/connectors/contrib/__init__.py Suspicious/requirements.txt
git commit -m "feat(connectors): case_search connector indexing cases in Elasticsearch"
```

---

### Task 2: Use ES ids in the investigation search

**Files:**
- Modify: `api/views/investigations.py:150-181` (the `if search:` block of `filter_case_queryset`) and the imports at the top
- Create: `api/tests/test_investigation_search_es.py`

**Interfaces:**
- Consumes: `connectors.contrib.case_search.service.search_case_ids(query: str | None) -> list[int] | None`

- [ ] **Step 1: Write the failing test**

`api/tests/test_investigation_search_es.py`:

```python
from unittest import mock

from django.contrib.auth.models import Group, User
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from case_handler.models import Case


@override_settings(ROOT_URLCONF="suspicious.urls")
class InvestigationSearchEsTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("cert", "c@x.io", "pw-12345")
        cls.user.groups.add(Group.objects.get_or_create(name="CERT")[0])
        cls.a = Case.objects.create(description="alpha only", reporter=cls.user)
        cls.b = Case.objects.create(description="beta only", reporter=cls.user)

    def setUp(self):
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    def _ids(self, q):
        r = self.client.get("/api/investigations/", {"search": q})
        self.assertEqual(r.status_code, 200)
        body = r.json()
        rows = body["results"] if isinstance(body, dict) and "results" in body else body
        return sorted(row["id"] for row in rows)

    def _patch(self, ret):
        return mock.patch("api.views.investigations.search_case_ids", return_value=ret)

    def test_es_ids_restrict_the_list(self):
        with self._patch([self.b.pk]):
            self.assertEqual(self._ids("whatever"), [self.b.pk])

    def test_empty_es_result_gives_empty_page(self):
        with self._patch([]):
            self.assertEqual(self._ids("nomatch"), [])

    def test_none_falls_back_to_orm_search(self):
        with self._patch(None):
            self.assertEqual(self._ids("alpha"), [self.a.pk])

    def test_numeric_search_still_matches_case_id(self):
        # ES returns nothing, but a digits-only search of >= 3 chars must still find the pk.
        case = Case.objects.create(id=424242, description="gamma", reporter=self.user)
        with self._patch([]):
            self.assertEqual(self._ids("424242"), [case.pk])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `ww test backend api.tests.test_investigation_search_es`
Expected: FAIL with `AttributeError: ... does not have the attribute 'search_case_ids'`.

- [ ] **Step 3: Write minimal implementation**

In `api/views/investigations.py` add to the imports:

```python
from connectors.contrib.case_search.service import search_case_ids
```

Replace the body of `if search:` (currently builds `id_q`/`text_q`, then `queryset.filter(id_q | text_q).distinct()`) with:

```python
        if search:
            id_q = Q(pk=int(search)) if search.strip().isdigit() else Q()
            es_ids = search_case_ids(search)
            if es_ids is not None:
                # ES answered: the text match is a plain pk filter (no joins, no distinct).
                queryset = queryset.filter(id_q | Q(pk__in=es_ids))
            else:
                text_q = (
                    Q(description__icontains=search)
                    | Q(reporter__email__icontains=search)
                    | Q(reporter__username__icontains=search)
                    | Q(fileOrMail__mail__subject__icontains=search)
                    | Q(fileOrMail__file__file_path__icontains=search)
                    | Q(nonFileIocs__url__address__icontains=search)
                    | Q(nonFileIocs__ip__address__icontains=search)
                    | Q(nonFileIocs__hash__value__icontains=search)
                    | Q(observable_group__artifacts__url__address__icontains=search)
                    | Q(observable_group__artifacts__ip__address__icontains=search)
                    | Q(observable_group__artifacts__hash__value__icontains=search)
                    | Q(observable_group__artifacts__domain__value__icontains=search)
                )
                # .distinct(): observable_group__artifacts is a reverse FK, so the
                # join fans a group case out to one row per indicator.
                queryset = queryset.filter(id_q | text_q).distinct()
```

Keep the original comments above `id_q`/`text_q` if they still apply; the `text_q` clauses must stay exactly as they are in the file today.

Edge: `Q()` is empty for non-numeric search, so `Q() | Q(pk__in=ids)` equals `Q(pk__in=ids)`; with `ids == []` this is an empty queryset (Django short-circuits `pk__in=[]`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `ww test backend api.tests`
Expected: PASS (new tests plus the existing API suite, which runs with the connector disabled and so takes the ORM path).

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/api/views/investigations.py Suspicious/Suspicious/api/tests/test_investigation_search_es.py
git commit -m "feat(api): investigation search uses the ES case index when enabled"
```

---

### Task 3: `reindex_cases` management command

**Files:**
- Create: `connectors/management/commands/reindex_cases.py`
- Create: `connectors/contrib/case_search/tests/test_reindex_command.py`

**Interfaces:**
- Consumes: `service.get_client`, `service.ensure_index`, `service.bulk_index(client, index, cases) -> (ok, errors)`, `service.CASE_RELATED`

- [ ] **Step 1: Write the failing test**

`connectors/contrib/case_search/tests/test_reindex_command.py`:

```python
from datetime import timedelta
from io import StringIO
from unittest import mock

from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from case_handler.models import Case
from connectors.contrib.case_search import service


class ReindexCommandTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("alice", "a@x.io", "pw")
        cls.old = Case.objects.create(description="old", reporter=cls.user)
        cls.new = Case.objects.create(description="new", reporter=cls.user)
        Case.objects.filter(pk=cls.old.pk).update(last_update=timezone.now() - timedelta(days=30))

    def _run(self, *args):
        out = StringIO()
        with mock.patch.object(service, "get_client") as gc, \
                mock.patch.object(service, "bulk_index", return_value=(2, 0)) as bulk:
            gc.return_value.indices.exists.return_value = True
            call_command("reindex_cases", *args, stdout=out)
        return bulk, out.getvalue()

    def test_indexes_all_cases(self):
        bulk, out = self._run()
        cases = list(bulk.call_args.args[2])
        self.assertEqual({c.pk for c in cases}, {self.old.pk, self.new.pk})
        self.assertIn("2 indexed", out)

    def test_since_limits_to_recently_updated(self):
        since = (timezone.now() - timedelta(days=1)).date().isoformat()
        bulk, _ = self._run("--since", since)
        self.assertEqual({c.pk for c in bulk.call_args.args[2]}, {self.new.pk})

    def test_bad_date_is_a_command_error(self):
        from django.core.management.base import CommandError

        with self.assertRaises(CommandError):
            call_command("reindex_cases", "--since", "not-a-date")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `ww test backend connectors.contrib.case_search.tests.test_reindex_command`
Expected: FAIL with `Unknown command: 'reindex_cases'`.

- [ ] **Step 3: Write minimal implementation**

`connectors/management/commands/reindex_cases.py`:

```python
"""Bulk-(re)index cases into the case_search Elasticsearch index.

Run once before enabling the case_search connector, and to repair drift."""
from django.core.management.base import BaseCommand, CommandError
from django.utils.dateparse import parse_date

from case_handler.models import Case
from connectors.contrib.case_search import service
from settings.config import get_section


class Command(BaseCommand):
    help = "Index cases into Elasticsearch (all, or those updated since --since)."

    def add_arguments(self, parser):
        parser.add_argument("--since", help="YYYY-MM-DD: only cases updated on/after this date")

    def handle(self, *args, **opts):
        cases = Case.objects.select_related(*service.CASE_RELATED).order_by("pk")
        if opts["since"]:
            since = parse_date(opts["since"])
            if since is None:
                raise CommandError(f"invalid --since date: {opts['since']!r}")
            cases = cases.filter(last_update__date__gte=since)

        config = get_section("integrations.case_search")
        index = config.get("index") or service.DEFAULT_INDEX
        client = service.get_client(config, timeout=service.INDEX_TIMEOUT * 6)
        service.ensure_index(client, index)
        ok, errors = service.bulk_index(client, index, cases.iterator(chunk_size=500))
        self.stdout.write(f"{ok} indexed, {errors} errors (index {index})")
        if errors:
            raise CommandError(f"{errors} documents failed to index")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `ww test backend connectors`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/connectors/management/commands/reindex_cases.py Suspicious/Suspicious/connectors/contrib/case_search/tests/test_reindex_command.py
git commit -m "feat(connectors): reindex_cases command for the case_search index"
```

---

### Task 4: Live verification, docs and spec alignment

**Files:**
- Modify: `docs/components/backend/connectors.md` (add a `case_search` section)
- Modify: `docs/specs/2026-10-07-case-search-elasticsearch-design.md` (align with decisions made while planning, see Step 3)
- Create: `connectors/contrib/case_search/tests/test_live_es.py` (skipped unless `ES_TEST_URL` is set)

- [ ] **Step 1: Write the live ES test (skipped by default)**

```python
import os
import uuid
from unittest import skipUnless

from django.contrib.auth.models import User
from django.test import TestCase

from case_handler.models import Case, CaseHasNonFileIocs
from connectors.contrib.case_search import service
from url_process.models import URL

ES_URL = os.environ.get("ES_TEST_URL")


@skipUnless(ES_URL, "set ES_TEST_URL to run against a real Elasticsearch")
class LiveEsTests(TestCase):
    def test_substring_search_roundtrip(self):
        config = {"url": ES_URL}
        client = service.get_client(config, timeout=10)
        index = f"suspicious-cases-test-{uuid.uuid4().hex[:8]}"
        try:
            service.ensure_index(client, index)
            user = User.objects.create_user("alice", "alice@x.io", "pw")
            case = Case.objects.create(description="d", reporter=user)
            url = URL.objects.create(address="http://phish-login.evil.test/a")
            case.nonFileIocs = CaseHasNonFileIocs.objects.create(case=case, url=url)
            case.save()
            case = Case.objects.select_related(*service.CASE_RELATED).get(pk=case.pk)
            service.index_case(client, index, case)
            client.indices.refresh(index=index)

            self.assertEqual(service.search_ids(client, index, "EVIL.te"), [case.pk])
            self.assertEqual(service.search_ids(client, index, "login.evil"), [case.pk])
            self.assertEqual(service.search_ids(client, index, "zzzzz"), [])
        finally:
            client.indices.delete(index=index, ignore_unavailable=True)
```

- [ ] **Step 2: Rebuild the image and run it against the dev ES**

The image needs the new dependency, then the test runs against the dev cluster (the `elasticsearch` service is up as Cortex's dependency).

```bash
cd deployment
docker compose --env-file .env build suspicious
docker compose --env-file .env run --rm --no-deps -e ES_TEST_URL=http://elasticsearch:9200 \
  suspicious python manage.py test connectors.contrib.case_search.tests.test_live_es
```

Expected: `OK` (1 test, not skipped). If the run cannot reach `elasticsearch`, drop `--no-deps`.

Then verify end to end on the dev stack:

```bash
docker compose --env-file .env up -d --force-recreate --no-deps suspicious suspicious_celery suspicious_celery_beat
docker compose --env-file .env exec suspicious python manage.py reindex_cases
```

Order: enable `case_search` first (Settings UI or `PATCH /api/connectors/case_search/` with `{"enabled": true}`), then run the reindex above; events for a disabled connector are dropped, and if reindexing ran first, re-run with `--since <date of the first run>`.

Expected: `<n> indexed, 0 errors (index suspicious-cases)`. Then search the investigations page for a fragment of a known URL/subject: results match the ORM search. Stop `elasticsearch` (`docker compose stop elasticsearch`) and search again: still returns results (fallback), then start it again.

- [ ] **Step 3: Docs and spec alignment**

Add to `docs/components/backend/connectors.md` a `case_search` section: purpose, config keys (`integrations.case_search.url|index|timeout_seconds`), the enable procedure (enable first, then run `reindex_cases`), the 3–20 character rule, and the fallback behavior.

Edit the spec so it matches what the plan builds:
- Config section is `integrations.case_search` (not `integrations.elasticsearch`), since connectors own `integrations.<connector name>`.
- Queries longer than 20 characters also use the ORM path (the keyword search analyzer matches the whole query against 3–20 character ngrams).
- Remove "open circuit" from the fallback description (no breaker around the ES client; timeout plus fallback is the protection).
- Replace "the `compose.ci.yaml` already starts one" with "the live ES test runs only when `ES_TEST_URL` is set; CI's compose stub has no Elasticsearch".

- [ ] **Step 4: Full backend suite**

Run: `ww test backend`
Expected: PASS. Then `rm -f Suspicious/Suspicious/gunicorn.conf.py` and `git status` shows only the files above.

- [ ] **Step 5: Commit**

```bash
git add docs/components/backend/connectors.md docs/specs/2026-10-07-case-search-elasticsearch-design.md Suspicious/Suspicious/connectors/contrib/case_search/tests/test_live_es.py
git commit -m "docs(connectors): document case_search; add live ES test; align spec"
```
