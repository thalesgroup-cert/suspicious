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

Enable: run `python manage.py reindex_cases`, then enable `case_search` in
the admin (`/admin/connectors/connectorstate/`).

Only queries of 3 to 20 characters use Elasticsearch (ngram limits); shorter
or longer queries use the ORM search. Any Elasticsearch error or timeout logs
a warning and falls back to the ORM search.

The live test (`connectors.contrib.case_search.tests.test_live_es`) runs only
when `ES_TEST_URL` is set.
