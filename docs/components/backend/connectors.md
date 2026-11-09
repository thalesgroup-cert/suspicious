# connectors

Plugin framework every integration with an external system is built on. The
ten built-in connectors are `thehive`, `misp`, `watcher`, `smtp_notify`,
`chromadb`, `ai_narration`, `case_search`, `elastic_siem`, `xsoar` and
`ai_model`. The framework provides registry, event dispatch, retry + circuit breaker, and a
`ConnectorDelivery` audit ledger.

See [`Suspicious/Suspicious/connectors/README.md`](https://github.com/thalesgroup-cert/suspicious/blob/main/Suspicious/Suspicious/connectors/README.md)
for the framework internals and the built-in connector table, and
[Connectors (author guide)](../../connectors.md) for writing a new one.

## ai_model

The mail AI classifier. It is off by default (`enabled_by_default=False`).

- **Provides** `mail_ai`: a mail case is handed to it instead of a Cortex AI job. A Celery task posts
  the mail text to the model server's `/v2` API (`http://ai_inference:8090` on `suspicious_net`,
  bearer token `AI_INFERENCE_TOKEN`) and stores the answer as one `AiAssessment` per case plus the
  case's AI result, score, confidence and category. Only one connector may provide `mail_ai`.
- **Events:** `case_finalised` (the only event it subscribes to; it also has a daily `label-sync`
  schedule). The hook only queues `connectors.tasks.run_campaign_detection`, which
  runs campaign detection outside the connector's circuit breaker and sends `campaign_updated` (the
  TheHive campaign alert) when a case creates or joins a campaign.
- **Config** (`integrations.ai_model`): `url` (default `http://ai_inference:8090`), `token`
  (secret, required), `timeout_seconds` (default 20). Label sync from a review mailbox:
  `imap_host` (empty disables the sync), `imap_port` (993), `imap_user`, `imap_password` (secret),
  `imap_use_ssl` (true), `imap_folders` (comma-separated, default the known review folders; the
  digit prefix of a folder name gives the class). Scheduled retrain: `retrain_enabled` (false) and
  `retrain_interval_days` (30). Details: [`ai_model` app](ai_model.md).
- **Health check:** `/v2/health/ready`, then the token against `/v2/models/ai_mail`; it also reports
  when the `chromadb` cleanup connector watches another collection than `suspicious_mails`.

Without it, a mail case has no AI vote (`results_ai` is set to `Inconclusive`) and no campaign
detection. Scoring then finalises most mails that the analyzer count does not make `Dangerous` as
`Inconclusive` (rule `analysis-incomplete`) instead of `Safe` or `Suspicious`, and the submitter's
notification mail, the TheHive challenge text and the dashboards show that verdict. Upgrade step:
enable `ai_model` (and set its `url` and `token`) as part of the upgrade.
`python manage.py ai_model_campaign_replay <campaign_ref>` replays a campaign the Cortex AI path built
through its detection. While a model version is the shadow, `case_finalised` also queues a campaign
dry run for it, and the `/api/ai-model/` endpoints (Admin and CISO read, Admin write) manage shadow,
promotion and rollback. Setup, failures, the replay command and the runbook:
[AI / ML Analyzers](../analyzers.md).

## case_search

Optional Elasticsearch-backed substring search for the investigations page.
Cases are indexed (description, subject, sender, file name, observables) and
the search box asks Elasticsearch for matching case ids, then the normal
scoped queryset filters by those ids.

Config in `settings.json`: `integrations.case_search.url`,
`integrations.case_search.index`, `integrations.case_search.timeout_seconds`,
and optionally `integrations.case_search.username` / `password`. Blank
credentials with the default URL use the in-stack `suspicious_app` account
(`ES_SUSPICIOUS_USER` / `ES_SUSPICIOUS_PASSWORD`); a custom URL never receives
those internal credentials.

Cortex logs in to Elasticsearch as `cortex_app` through `-Dsearch.user` /
`-Dsearch.password` in `JAVA_OPTS`. If an operator-owned Cortex
`application.conf` already sets `search.user` / `search.password`, that file
wins over the `JAVA_OPTS` values.

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
when `ES_TEST_URL` is set. Elasticsearch now requires authentication, so also
set `ES_TEST_USER` and `ES_TEST_PASSWORD` (a user allowed to manage
`suspicious-*` indices, e.g. `suspicious_app`).

## elastic_siem

Indexes one ECS document per case (`_id` = case id) into an operator-supplied
Elasticsearch for Elastic Security. Subscribes to `case_finalised` and
`case_modified`; only cases at or above `min_verdict` (default `Suspicious`) are
sent, and a case downgraded below it only updates an existing document. Config
(`integrations.elastic_siem`): `url`, `api_key` (secret, the base64 `encoded`
value), `index` (default `logs-suspicious.case`), `min_verdict`, `verify_tls`,
`timeout_seconds`, `create_index`, `ui_base_url`. Backfill with
`python manage.py reindex_siem [--since YYYY-MM-DD] [--min-verdict V] [--dry-run]`.
Off by default. Full description:
[connectors README](https://github.com/thalesgroup-cert/suspicious/blob/main/Suspicious/Suspicious/connectors/README.md#elastic_siem).

## xsoar

Opens one Cortex XSOAR incident per finalised case at or above `min_verdict`
(default `Suspicious`), recorded in `ConnectorLink` so a replay opens nothing.
Subscribes to `case_finalised`. Cases whose `external_ref` starts with
`skip_ref_prefix` (default `xsoar:`) came from an XSOAR playbook and are not
pushed back. Config (`integrations.xsoar`): `url`, `api_key` (secret),
`api_key_id` (XSOAR 8 only), `incident_type`, `min_verdict`,
`create_investigation`, `skip_ref_prefix`, `verify_tls`, `timeout_seconds`,
`ui_base_url`. Off by default. Full description:
[connectors README](https://github.com/thalesgroup-cert/suspicious/blob/main/Suspicious/Suspicious/connectors/README.md#xsoar).
