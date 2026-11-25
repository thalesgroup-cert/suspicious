# connectors

Plugin framework every integration with an external system is built on. The
eleven built-in connectors are `thehive`, `misp`, `watcher`, `smtp_notify`,
`chromadb`, `ai_narration`, `case_search`, `elastic_siem`, `xsoar`,
`ai_model` and `cortex`. The framework provides registry, event dispatch, retry + circuit breaker, and a
`ConnectorDelivery` audit ledger.

See [`Suspicious/Suspicious/connectors/README.md`](https://github.com/thalesgroup-cert/suspicious/blob/main/Suspicious/Suspicious/connectors/README.md)
for the framework internals and the built-in connector table, and
[Connectors (author guide)](../../connectors.md) for writing a new one.

## Analysis engines

A connector whose manifest sets `provides="analysis"` is an analysis engine. `connectors/engines.py`
is the only code the pipeline calls to start analyzer jobs and read their results; Cortex is the
first engine. An engine implements four operations and never touches the database:

| Operation | Returns |
|---|---|
| `catalog(data_type=None, name=None)` | the analyzers it offers (`CatalogEntry`: id, name, data types) |
| `start(analyzer, data_type, value)` | a `StartResult` (external job id, and optionally a finished result), or `None` for a routine refusal |
| `fetch(job_id)` | a `FetchResult` in one of three states, below |
| `webhook(headers, payload)` (optional) | the job ids an authenticated callback announces; `None` when the caller is not authenticated |

`fetch` has three outcomes. **result**: a status (`Waiting`, `InProgress`, `Success`, `Failure`)
and, on success, `summary` (with `taxonomies`) and `full`, stored and scored as Cortex reports
always were. **gone**: the engine says the job no longer exists; the row becomes `Deleted`.
**unknown**: the engine could not be reached (network error, open breaker); the row is left alone
and a later pass retries. An engine must never answer "gone" for a job it merely could not reach.

- **One engine or many.** Any number of `analysis` connectors may be enabled (the
  one-per-kind rule is for `mail_ai` only). `engines.dispatch` asks every enabled engine for its
  catalogue and starts the analyzers the selection policy picks (roles from
  `integrations.cortex.analyzers.*`, whichever engine offers the name), so one case can hold rows
  from several engines and reconcile waits until all of them are closed. With none enabled,
  dispatch writes no rows and the case finalises as "no analyzer applicable". A **disabled**
  engine starts nothing, but its pending rows are still fetched, so a case in flight completes.
- **Name ownership.** `Analyzer.source` names the connector that owns the row; `Analyzer.name`
  stays unique. An engine offering a name another source owns is skipped (logged) by both the
  catalogue sync and dispatch, and the sync deactivates only its own rows. Cortex keeps its raw
  ids; any other engine stores `<connector>:<id>` in `analyzer_cortex_id` and `<connector>-<id>`
  in `cortex_job_id`.
- **Webhook.** `POST /api/connectors/<name>/webhook/` is the generic route: the engine
  authenticates the call itself, announced job ids are deduplicated in cache and the owning cases
  are reconciled. `/api/cortex/webhook/` forwards to it, so Cortex's webhook URL and secret are
  unchanged. A disabled engine's webhook is still accepted.
- **Stale jobs.** `fail_stale_jobs` fails a pending row once it is older than its own engine's
  `stale_job_timeout_seconds` (7200 when absent or when the engine is no longer registered).
- **Delivery ledger.** A `ConnectorDelivery` row (event `start`) is written for each **failed**
  start only, with the analyzer name and the exception class. A successful start is recorded by its
  `CaseAnalyzerJob`; a refusal (the engine declined the input) is a log line, and fetches are not
  recorded.

## cortex

Category Analysis, provides `analysis`, enabled by default. Config is the existing
`integrations.cortex` section (`url`, `api_key`, `webhook_secret`, `stale_job_timeout_seconds`,
`analyzers.*`), so `settings.json` needs no change. The connector starts, fetches and announces
Cortex jobs through the engine layer above, syncs the analyzer catalogue
into the `Analyzer` table every 60 s (the old `sync-cortex` beat entry is gone; the `sync_cortex`
task forwards to it) and reports health from `GET <url>/api/analyzer` with the API key, so a rejected key shows
as not ok. The health detail also lists configured `analyzers.*` roles Cortex does not offer,
the inactive analyzer count, jobs pending over 30 minutes and the age of the last webhook (an
early sign of a broken callback). A failed sync is a failed delivery and is retried, except a
rejected API key, which waits for an operator. The
webhook reads `webhook_secret` from the connector config, so an edit applies without a restart.
Unconfigured, it reports not ok and the sync does nothing. Disabling the cortex connector stops
all new Cortex analysis. Disabling the last enabled `analysis` connector needs
`"force": true` on `PATCH /api/connectors/<name>/` (otherwise 409, code `last_analysis_connector`).

A Cortex outage shows in the connector health, the `cortex` breaker state and the logs, but not as
failed-start deliveries: the catalogue lookup fails quietly, so nothing reaches `start`. Failed-start
rows appear for intermittent errors, auth failures and similar.

- **Upgrade:** before upgrading, check that Settings > Connectors shows Cortex **enabled**. Until
  this release the flag only gated the analyzer sync, so a Cortex connector switched off then now
  stops all new Cortex analysis. The webhook URL and secret are unchanged.
- On upgrade, disable any old Cortex-side `AI_Mail_Analyzer` analyzer in Cortex. Otherwise the sync logs an ERROR about it every minute, because the row now belongs to the `ai_model` connector.
- `/api/cortex/webhook/` reads its secret through the runtime config layer (Vault-backed, cached 60 s) instead of only at boot, and falls back to `CORTEX_WEBHOOK_SECRET` when that config cannot be read.

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
