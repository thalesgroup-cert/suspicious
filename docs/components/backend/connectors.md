# connectors

Plugin framework every integration with an external system (TheHive, MISP,
Watcher, ChromaDB, SMTP notifications, the `ai_narration` LLM connector) is
built on: registry, event dispatch, retry + circuit breaker, and a
`ConnectorDelivery` audit ledger.

See [`Suspicious/Suspicious/connectors/README.md`](https://github.com/thalesgroup-cert/suspicious/blob/main/Suspicious/Suspicious/connectors/README.md)
for the framework internals and the built-in connector table, and
[Connectors (author guide)](../../connectors.md) for writing a new one.

## case_search

Optional Elasticsearch-backed substring search for the investigations page.
Cases are indexed (description, subject, sender, file name, observables) and
the search box asks Elasticsearch for matching case ids, then the normal
scoped queryset filters by those ids.

Config in `settings.json`: `integrations.case_search.url`,
`integrations.case_search.index`, `integrations.case_search.timeout_seconds`.

Enable: first enable `case_search` (Settings UI, or `PATCH /api/connectors/case_search/`
with body `{"enabled": true}`; admin/CERT only, `enabled` must be a boolean), then
run `python manage.py reindex_cases`. Events for a disabled connector are dropped
and unrecoverable, so a case created between a reindex and enabling would never be
indexed. If you reindexed first, re-run `reindex_cases --since <date of the first run>`.

Deliveries that exhausted their retries can be re-emitted with
`python manage.py redeliver_connector case_search [--since 2d] [--dry-run]`
(re-emits `case_finalised` for cases whose latest delivery failed or was skipped).

Only queries of 3 to 20 characters use Elasticsearch (ngram limits); shorter
or longer queries use the ORM search. Any Elasticsearch error or timeout logs
a warning and falls back to the ORM search.

The live test (`connectors.contrib.case_search.tests.test_live_es`) runs only
when `ES_TEST_URL` is set.
