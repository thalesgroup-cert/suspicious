# Analysis engines as connectors: design

Status: approved by the owner 2026-11-16, with the last-engine guard. Builds on the feasibility write-up
`2026-11-16-cortex-connector-feasibility.md`. Read from `main` at `db64b71f`.

## Intent

Cortex is treated like every other integration, and the platform can rely on the AI connector
or any future connector for analysis as much as it relies on Cortex.

Today the pipeline *is* a Cortex client: six call sites start Cortex jobs, reconcile asks Cortex
for results, and the settings key, the webhook and the analyzer sync are named after it. After
this work the pipeline asks "which enabled connectors can analyse this observable?" and Cortex
is one answer.

## Goals

1. Cortex is a connector: listed, enabled, configured, tested and observed through the same
   endpoints and Settings screens as TheHive or MISP.
2. One contract for every analysis connector. A job-based engine (Cortex) and an instant answer
   (a lookup, the AI classifier) implement the same three operations.
3. Several analysis connectors can be enabled at once and contribute jobs to the same case.
4. The pipeline runs, and finalises cases correctly, with Cortex disabled.
5. An existing deployment upgrades with no configuration change and no change in verdicts.

## Non-goals

- Renaming the `cortex_job` app, `cortex_job_id`, `analyzer_cortex_id`, or the
  `score_process/scoring/cortex_analyzers/` package.
- Any change to scoring, weights, tiers or the verdict rules.
- Writing a native engine (VirusTotal, urlscan, ...). The design makes one possible; none is
  in scope.
- Moving the mail AI verdict onto the new contract. It is the last step below and gets its own
  design when it starts.
- Replacing Cortex's own `application.conf`.

## Anti-goals

The work has failed, even if it runs, when:

- a case's verdict differs from what the current code gives for the same stored reports;
- an upgrade leaves Cortex disabled and analysis stops without an error anyone sees;
- the analyzer-selection rules exist in two places;
- a connector author has to know about Cortex to write an engine.

## Constraints

- `python manage.py backtest_scoring` output is byte-identical before and after each step.
- No migration on `AnalyzerReport` (it holds `report_full`, the largest table).
- `settings.json` written for the current release keeps working unchanged. The connector is
  named `cortex`, so its config section is the existing `integrations.cortex`.
- A deployed Cortex keeps posting to `/api/cortex/webhook/` with its current secret.
- The `ai_model` connector's `mail_ai` slot keeps working as it does today until its own step.

## Approaches

1. **Operations only.** A `cortex` connector for config, health and schedules; job starts and
   result fetching stay hard-wired. Small and safe, but Cortex stays the only possible engine.
   It is step 1 here, not the whole design.
2. **One contract for every analysis connector (chosen).** Any connector can offer analyzers,
   start a job and report a result; an instant answer is a job that is already finished when it
   starts. Chosen because the stated goal is that Cortex, the AI connector and future connectors
   are the same kind of thing.
3. **Two contracts side by side.** Keep the synchronous `mail_ai` slot and add a separate
   asynchronous one. Less work now; rejected because it keeps the split the goal removes.
4. **Full extraction with renames.** Approach 2 plus engine-neutral names for the app, columns
   and parser package. Rejected: migrations on the largest table, about 40 import sites and
   about 100 test files, for no change in behaviour.

## Design

### The contract

A new provider kind, `analysis`, next to `mail_ai` in `connectors/base.py`. Unlike `mail_ai`,
any number of `analysis` connectors may be enabled; the one-per-kind check in
`ConnectorStateView` applies to `mail_ai` only.

A connector whose manifest sets `provides="analysis"` implements:

| Operation | Input | Returns |
|---|---|---|
| `catalog(data_type=None, name=None)` | optional filter | the analyzers it offers: stable id, name, data types |
| `start(analyzer, data_type, value)` | one offered analyzer, the observable | an external job id, and optionally a finished result |
| `fetch(job_id)` | an external job id | status and, on success, `summary`, `taxonomies`, `full`; "gone" when the engine says the job no longer exists; "unknown" when it could not be reached |
| `webhook(headers, payload)` (optional) | an inbound callback | the external job ids it announces, after authenticating the caller itself |

Rules of the contract:

- `start` returning a finished result is the instant case. The engine layer stores it and
  closes the ledger row in the same transaction; `fetch` is never called for that job.
- `fetch` distinguishes three outcomes that today's code already separates: a result, "gone"
  (Cortex 404, the row becomes `Deleted`), and "unknown" (network error, open breaker: the row
  is left alone and a later pass retries). An engine must never report "gone" for a job it
  merely could not reach.
- A stored result uses the shape `update_report_instance` writes today: `summary`,
  `summary.taxonomies`, `full`. The existing parser registry scores it; an analyzer with no
  bespoke parser falls back to `DefaultTaxonomyParser`.
- The connector never touches the database. Only the engine layer writes `AnalyzerReport` and
  `CaseAnalyzerJob`.
- Every call into a connector runs under that connector's circuit breaker, as
  `run_provider_analysis` does today.

### The engine layer

One new module, `connectors/engines.py`, is the only code the pipeline calls. It owns what
`CortexJob.run_analyzer`, `CortexJobManager.update_single_job` and the webhook view do around
the Cortex calls today.

- **`dispatch(value, data_type, case)`** replaces `CortexJob().launch_cortex_jobs(...)` at its
  six call sites. For each enabled `analysis` connector it asks for the catalog, applies the
  selection policy, calls `start`, and writes the `AnalyzerReport` and `CaseAnalyzerJob` rows
  exactly as `run_analyzer` does (same fields, same transaction). A connector that fails or
  refuses one analyzer does not stop the others.
- **`refresh(case_analyzer_job)`** replaces `mgr.update_single_job(caj)` in
  `reconcile_case_core`. It finds the engine from the row's analyzer, calls `fetch`, and applies
  the result with the logic of `get_cortex_jobs_results`, including scoring the report on
  success and the per-request job and report caches. Rows with no `analyzer_report` are skipped,
  as today, so `mail_ai` rows are untouched.
- **`handle_webhook(connector_name, headers, payload)`** keeps the jobId dedup in cache and the
  ledger lookup from `cortex_webhook.py`, then queues `reconcile_case` per owning case.
- **`sync_catalog(connector_name)`** replaces `sync_cortex_analyzers`: upsert `Analyzer` rows
  from the catalog and deactivate rows of *that connector* that are no longer offered.

`reconcile_case_core` changes in one line. The state machine, `finalise`, derived observables
and the `case_finalised` event are not touched.

### Which engine owns an analyzer

`Analyzer` gains one column: `source`, the connector name, default `"cortex"`. It is a small
table; the migration backfills every existing row to `cortex` and sets the AI vote's row (the
one named by `ai_analyzer_name()`) to `ai_model`.

- `refresh` and the stale-job timeout find the engine through `caj.analyzer.source`.
- `sync_catalog` deactivates only rows whose `source` is the connector being synced. This
  replaces today's special case that spares the AI row by name.
- `Analyzer.name` stays unique across the platform. If a second engine offers a name that
  another source already owns, `sync_catalog` skips it and logs an error; `dispatch` never
  starts it. Two engines cannot both score under one analyzer row.
- Ids in existing columns: Cortex keeps its raw ids, so stored rows and webhook lookups do not
  change. Any other engine stores `"<connector>:<id>"` in `analyzer_cortex_id` and
  `"<connector>-<id>"` in `cortex_job_id`, within the existing 50 characters.

### Selection policy

One function in `connectors/engines.py` holds the rules that `launch_cortex_jobs`,
`get_file_analyzers` and `get_analyzers_by_type` hold today, unchanged in effect:

- `mail_body`: only the analyzer in the `yara` role.
- `mail_header`: only the analyzer in the `header` role.
- `file`: the `yara`, `file_info` and `sandbox` roles; for an `.eml` file, none of the `ai`,
  `yara`, `sandbox` or `header` roles.
- anything else: every analyzer offered for that data type, minus the `yara`, `sandbox` and
  `header` roles.

Roles keep coming from `integrations.cortex.analyzers.*`, read as platform roles ("the analyzer
named X plays the YARA role"), whichever connector offers that name. Moving the roles to a
neutral settings key is left out: it would break existing `settings.json` files for no gain.

The translation "a `mail_body` is sent to Cortex as a `file`" and the `tlp` value are Cortex's
business and move into the Cortex connector. `get_data_value` (how a model instance becomes the
string or path to analyse) stays generic and moves to the engine layer.

The catalog is asked live on every dispatch, as today. Caching it is a later optimisation and
must not be added in this work.

### The Cortex connector

`connectors/contrib/cortex/`, registered in `BUILTIN_CONNECTOR_PATHS`.

- **Manifest.** `name="cortex"`, `provides="analysis"`, `category="Analysis"`,
  **`enabled_by_default=True`**. Config schema: `url` (url, required), `api_key` (secret),
  `webhook_secret` (secret), `stale_job_timeout_seconds` (int, default 7200),
  `analyzers.yara`, `analyzers.sandbox`, `analyzers.header`, `analyzers.file_info`,
  `analyzers.ai` (str). One schedule for the analyzer sync, at the interval `sync_cortex` runs
  at today.
- **Operations.** `catalog`, `start`, `fetch` wrap the `cortex4py` calls now in
  `cortex_and_job_management.py` and `sync_cortex.py` (including the `GET /api/analyzer`
  workaround and the trailing-slash trim). `webhook` checks `Authorization: Bearer <secret>`
  with `hmac.compare_digest` and returns the `jobId`. `health_check` is the probe
  `/api/health/` uses today. `sync` calls `engines.sync_catalog("cortex")` and keeps the check
  that every configured role names an analyzer Cortex really offers.
- **Breaker.** The connector name equals the existing breaker name `cortex`, so it is the same
  breaker; it gains the published state and reset that every connector has.

### Inbound webhooks

A generic route, `POST /api/connectors/<name>/webhook/`, with no authentication class: the
connector authenticates the caller. It answers 404 for an unknown connector, one that does not
provide `analysis`, or one with no `webhook` operation. `/api/cortex/webhook/` stays and
forwards to `cortex`, with the same status codes and bodies it returns today.

`CORTEX_WEBHOOK_SECRET` in Django settings is no longer read by the view; the connector reads
`webhook_secret` from its config section, which is the same Vault-backed value.

The webhook stays accepted when the connector is disabled, so jobs already running can finish.

### Enabled, disabled, absent

- **Disabled engine.** `dispatch` starts nothing on it. `refresh` still fetches results for its
  pending rows, so a case in flight completes. An engine disabled for good leaves any remaining
  rows to `fail_stale_jobs`.
- **No engine enabled.** `dispatch` writes no rows. The case finalises through the path that
  exists today for "no analyzer applicable"; its description no longer names Cortex.
- **Last-engine guard.** `PATCH /api/connectors/<name>/` refuses to disable the last enabled
  `analysis` connector with 409 and a message saying new cases would get no analysis, unless
  the request carries `"force": true`. The Settings UI shows that message as a confirmation and
  resends with `force`. A forced disable is logged at warning level with the user. The guard
  ships with step 1.
- **Stale jobs.** `fail_stale_jobs` uses each row's own engine timeout
  (`stale_job_timeout_seconds` in that connector's config, 7200 when absent) in place of the
  single Cortex value.
- **Health.** `/api/health/` keeps its `cortex` key and its rule that only the database and
  Redis decide the status code.

### What is recorded

`ConnectorDelivery` gets a row for each failed analyzer sync and, at most once an hour, a
successful one (a 60 s sync would otherwise add about 1,400 rows a day) and for each **failed** `start`, with the analyzer name in the error. A successful start
is already recorded by its `CaseAnalyzerJob` row, and fetches are too frequent to log.

### Compatibility kept on purpose

- `CortexJob` and `CortexJobManager` remain as thin forwarders to the engine layer until the
  tests that patch them by path are moved. No new code may call them.
- The `sync_cortex` task name remains registered and forwards to the connector sync, so a beat
  schedule persisted before the upgrade does not raise.
- `update_ongoing_cases` stays a platform task in `tasp`: it reconciles cases, whichever engine
  their jobs came from.

## Steps

Each is its own plan and ships alone.

1. **Cortex connector, operations only.** Manifest, config schema, health check, analyzer sync
   as its schedule, `Analyzer.source`. Job starts and fetches unchanged. Proves the upgrade
   path: after it, Cortex shows in Settings as enabled on an upgraded stack.
2. **The engine layer.** The contract, `connectors/engines.py`, Cortex behind it, the six call
   sites on `dispatch`, reconcile on `refresh`, the generic webhook route. Still one engine.
3. **A test engine.** An in-tree `analysis` connector, off by default, that answers instantly
   from fixed data. It proves "several engines per case" and "runs with Cortex disabled", and
   gives CI and the dev stack a pipeline with no Cortex container.
4. **The mail AI verdict on the contract** (own design). `ai_model` offers an analyzer and
   returns an instant result; writing the case's AI fields and the `AiAssessment` becomes what
   happens when that analyzer's result is stored. The `mail_ai` kind is then retired.

## Acceptance

- `backtest_scoring` byte-identical after steps 1, 2 and 3.
- Upgrade test: a database and `settings.json` from the current release, migrated, shows
  `cortex` enabled and analyses a submitted mail with no manual action.
- With `cortex` disabled and the test engine enabled, a submitted mail and a submitted URL both
  finalise, scored from the test engine's results.
- With both enabled, one case holds ledger rows from both and waits for both.
- A webhook to `/api/cortex/webhook/` and to `/api/connectors/cortex/webhook/` both reconcile
  the owning case; a wrong secret gets 401 on both.
- Disabling the only enabled analysis connector returns 409 without `force` and succeeds with
  it; disabling one of two succeeds without it.
- A failed `start` appears in `GET /api/connectors/cortex/deliveries/`.
- The full backend suite passes; the only test edits are import paths and patch targets.

## Left to the builder

- Exact dataclass names and signatures for the catalog entry, the start result and the fetch
  result.
- How the per-request job and report caches of `CortexJobManager` are carried into the engine
  layer.
- Whether the Cortex connector reuses `SessionCortexApi` in place or moves it.
- The interval for the analyzer-sync schedule (copy today's).
- The order in which tests that patch `CortexJob` are moved.

## Calls made here, not decided with the owner

- `Analyzer.source` as a new column (the alternative, parsing a prefix out of
  `analyzer_cortex_id`, would leave Cortex rows as the unmarked special case).
- Roles stay under `integrations.cortex.analyzers.*`.
- A disabled engine still has its in-flight jobs fetched.
- Analyzer names are unique across engines; a clash is refused, not merged.
- Only failed starts go to the delivery ledger.
- `category="Analysis"` for the connector list.
