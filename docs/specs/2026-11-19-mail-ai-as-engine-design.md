# The mail AI verdict as an analysis engine: design

Status: design for approval, 2026-11-19. Step 4 of `2026-11-16-analysis-engine-connectors-design.md`.
Read from `feat/fixture-analysis-engine` at `72d836ea`. The owner chose option 1 below ("deferred
jobs") on 2026-11-19.

## Intent

Today the `ai_model` connector is a second kind of thing next to Cortex: a `mail_ai` provider with
its own queue function, Celery task, result type and ledger writer. The goal set in step 1 was that
Cortex, the AI connector and any future connector are the same kind of thing, so the pipeline asks
"which enabled connectors can analyse this?" and nothing else. This step moves the mail AI verdict
onto the analysis-engine contract and retires the `mail_ai` slot.

Nothing the analyst sees or the scoring reads changes: the same case fields, the same
`AiAssessment`, the same verdicts.

## Goals

1. `ai_model` is an `analysis` connector. Its mail verdict is produced by an engine job, started by
   `engines.dispatch` like any other.
2. A job may run in a worker instead of at start (a new, generic "deferred" mode of the contract),
   with the retry, circuit-breaker and idempotency behaviour the AI path has today. Any slow engine
   can use it; the AI is the first.
3. A connector can react to its own stored result (a store-time hook), so the AI engine can write
   the case's AI fields and the `AiAssessment` as part of storing its result.
4. The `mail_ai` kind, `Connector.analyze`, `ProviderResult`, `queue_provider_analysis`,
   `queue_mail_ai`, `run_provider_analysis` and `finish_provider_analysis` are removed.
5. Verdicts stay byte-identical for the same inputs: a parity suite ported from the current tests
   proves it.

## Non-goals

- The inference server API, `AiAssessment`'s schema, the case AI fields, scoring, campaign
  detection, label sync, retraining, shadow promotion. None change.
- Putting the AI verdict through `AnalyzerReport` or the parser registry. It stays report-less, as
  today (`CaseAnalyzerJob` row with no report).
- A migration. Ledger job ids change format for new rows only.
- Renaming `ProviderUnavailable` (used across `ai_model`; it stays, in `connectors/providers.py`).

## Anti-goals

The work has failed, even if it runs, when:

- a case gets a different AI verdict, `results_ai`, `score_ai`, `confidence_ai`, `category_ai` or
  `AiAssessment` than the old path gives for the same mail and the same server answer;
- a mail whose AI job never ran or failed is not marked "AI missing" (`results_ai = Inconclusive`),
  because scoring would then use the model default "Suspicious";
- disabling Cortex while `ai_model` is enabled stops all analysis of URLs and files with no 409;
- an upgrade strands a case whose AI job was queued before it.

## Constraints

- No migration; nothing under `score_process/`; `backtest_scoring` identical (it does not cover this
  path, so the parity suite below is the real check).
- `settings.json` unchanged. The AI vote's analyzer name stays `ai_analyzer_name()`
  (`integrations.cortex.analyzers.ai`, default `AI_Mail_Analyzer`); the `ai_model` connector name
  and config section do not change.
- Retry and breaker behaviour of the AI job equals today's: a retryable `ProviderUnavailable` is
  retried twice with `5 * 2**n + uniform(0, 3)` seconds of delay, any other error fails the row at
  once, every call to the connector runs under the `ai_model` breaker, the row is claimed with a
  conditional UPDATE so a redelivery or `fail_stale_jobs` cannot double-close it.
- `ConnectorDelivery` rows for AI jobs keep `event="analyze"` (the deliveries view and the
  operator troubleshooting text name it).
- Commits: Conventional Commits, no `Co-Authored-By`.

## Approaches

1. **Deferred jobs (chosen).** The contract gains a generic deferred mode: `start` registers the job
   and the engine layer runs it in a Celery task. The AI is the first user. Removes the provider
   slot completely; costs a larger change in the engine layer.
2. **Instant at start.** `start()` calls the inference server inline and returns a finished result
   (the literal reading of the first design). Smaller, but it blocks the dispatch task for seconds
   per mail, runs retries inline, and blocks the feeder's mail pipeline. Rejected.
3. **Keep the provider slot.** Leave `mail_ai` as it is. Zero risk to the verdict path, but it keeps
   the split this work set out to remove. Rejected by the owner's goal; remains the fallback if the
   parity suite cannot be made to pass.

## Design

### Contract additions (`connectors/base.py`)

- **Data type `mail_archive`.** A case-level data type, not an observable: its "value" is the case
  id as a string. Only analyzers that declare it in `CatalogEntry.data_types` are offered for it.
- **`StartResult.deferred: bool = False`.** A start that returns `deferred=True` has accepted the
  job; its result will come from `Connector.run`.
- **`Connector.run(self, job_id: str, data_type: str, value: str) -> FetchResult`.** Executed in a
  worker by the engine layer for a deferred job. Returns the same `FetchResult` a fetch returns
  (state `result`, a status, an optional `payload`). It may raise `ProviderUnavailable` (retryable
  or not).
- **`FetchResult.payload: dict | None = None`.** Engine-specific data that is not a report body.
- **`Connector.on_started(self, case, analyzer_name: str) -> None`.** Called by `dispatch` right
  after it writes the ledger row of a deferred job, in the same transaction. Default does nothing.
- **`Connector.on_result(self, case, analyzer_name: str, result: FetchResult) -> None`.** Called by
  `run_engine_job` inside the transaction that stores a **deferred** job's outcome and closes its
  row, for a success **and for a failure** (`result.status == "Failure"`, with the reason in
  `payload["reason"]`). The other paths (`refresh`, the finished-at-start path) do not call it: no
  engine needs it there yet. Default does nothing.
- **`Connector.general_purpose: ClassVar[bool] = True`.** False for an engine that covers only part
  of the pipeline (the AI covers only `mail_archive`).

### Engine layer (`connectors/engines.py`, `connectors/tasks.py`)

- `dispatch(value, "mail_archive", case)` asks every enabled engine for
  `catalog(name=<ai role name>)`; the selection policy for `mail_archive` is "only the analyzer in
  the `ai` role". `get_data_value` returns `str(case.id)` for it.
- When `start` answers `deferred=True`, the engine layer writes the `CaseAnalyzerJob` row
  (`InProgress`, **no `AnalyzerReport`**, ledger id from `ledger_ids`) and enqueues
  `run_engine_job(job_row_id)` on commit.
- **`run_engine_job`** (replaces `run_provider_analysis`): skips when the row is no longer pending;
  runs `connector.run(...)` under that connector's breaker; retries only a retryable
  `ProviderUnavailable` (same delays); then claims the row with the conditional UPDATE, calls
  `connector.on_result` in the same transaction (for the final outcome: the result, or a
  `Failure` built from the last error), writes the `ConnectorDelivery(event="analyze")` row (`success`
  or `failed`, the error text on failure), closes the row (`Success` or `Failure`, `completed_at`)
  and queues `reconcile_case` on commit. The engine layer knows nothing about the AI: all AI rules
  live in the connector's hooks.
- **A deferred job runs even if its connector was disabled after the start** (the engine rule: a
  started job finishes), unlike today, where a disabled provider fails the row at once. One parity
  test changes for this.
- **AI missing, three places, all in `ai_model`.** (1) `ai_model.on_started` marks the AI missing
  at registration unless the case already has an assessment (today's rule in
  `queue_provider_analysis`), so a row closed by `fail_stale_jobs`, a lost enqueue or a dead worker
  leaves `results_ai = Inconclusive`, never the model default "Suspicious". (2)
  `ai_model.on_result` on a failure: AI missing unless an earlier assessment exists (today's rule in
  `finish_provider_analysis`). (3) A new helper `ai_model.mailinfo.dispatch_mail_ai(case)` is what
  `tasp.tasks.dispatch_case_analysis` and `gsubmission` call: it calls
  `engines.dispatch(value=case, data_type="mail_archive", case=case)` and, when that starts no job
  (no enabled engine offers the AI role, or every start was refused), calls `mark_ai_missing(case)`.
  `mark_ai_missing` and `has_assessment` move from `connectors/providers.py` to
  `ai_model/mailinfo.py`; `gsubmission`'s own `mark_ai_missing` call for a mail with no usable archive
  stays.
- The `provider-` ledger prefix is retired for new rows. Rows already open at upgrade keep it.

### The `ai_model` connector

- `provides` becomes `analysis`; `general_purpose = False`.
- `catalog(name=<ai role name>)` returns one entry (`id="ai_model:mail_classifier"`, the AI vote's
  analyzer name, `data_types=("mail_archive",)`); any other query returns `[]`. `start` returns
  `StartResult(job_id=<hex>, deferred=True)`.
- `run(job_id, "mail_archive", case_id)` is today's `analyze` body: read the mail text, call the
  inference server, map the answer, include the shadow answer when a shadow exists. It returns a
  `FetchResult` whose `payload` carries what `ProviderResult` carried (result, score, confidence,
  category, model version, assessment, shadow, reason). **Its `status` follows today's outcome
  exactly:** a normal server answer (it has a model version) is `Success` even when the class is
  INCONCLUSIVE; no archive, an unreadable archive, a server refusal ("can't tell") and an answer
  with no model version are `Failure` with the reason in the payload, because today
  `finish_provider_analysis` treats a result without a model version as a failure (row `Failure`,
  delivery `failed`, AI missing unless an earlier assessment exists).
- `on_result` is today's `finish_provider_analysis` write, moved: on `Success`, the case's AI
  fields, `AiAssessment` (all fields reset to defaults then the result's, as now), `apply_mail_info`,
  the shadow store in its own savepoint; on `Failure`, the AI-missing rule above and a warning in the
  log with the reason.

### Guard and statuses

- The last-engine guard counts another enabled `analysis` connector only if it is not inert **and**
  `general_purpose`. Disabling Cortex while only `ai_model` is enabled therefore needs `force`.
  The guard applies only when the connector being disabled is itself `general_purpose`: disabling
  `ai_model` never needs `force` (it analyses nothing general, so it is never "the last engine").
- `enabled_engines()` is unchanged; `ai_model` appears in it and dispatches only the `mail_archive`
  type because it offers nothing else.
- The one-enabled-per-kind check in `ConnectorStateView` is deleted with the `mail_ai` kind.

### Callers

`tasp.tasks.dispatch_case_analysis` and `gsubmission` replace `queue_mail_ai(case)` with
`ai_model.mailinfo.dispatch_mail_ai(case)` (see "AI missing" above). The intent label
`AI_ARCHIVE_INTENT` is kept (it is serialised into queued tasks).

### Upgrade

- The `ai_model` connector keeps its name, config and enabled state.
- A job queued by the old code before the upgrade is run by a task named `run_provider_analysis`
  that stays registered for one release and forwards to the new path (looking up the open ledger row
  by id); if the row is gone or closed it does nothing.
- `fail_stale_jobs` already uses the engine's own timeout and closes any row left pending.

## Acceptance

- **Parity suite:** the current tests of `finish_provider_analysis`, `run_provider_analysis`,
  `queue_provider_analysis` and `queue_mail_ai` (connectors/tests/test_providers.py,
  test_provider_dispatch.py, the ai_model tests) are ported to the new path with identical
  assertions on the case fields, `AiAssessment`, ledger rows and delivery rows: refused mail,
  unreadable archive, no archive, server down (retried twice, then AI missing), non-retryable error,
  shadow answer, redelivery after close, an earlier assessment kept when a later job fails.
- **No engine offers the AI role:** the case is marked AI missing and finalises as today.
- **A row that never completes:** a deferred AI row closed by `fail_stale_jobs` (or whose enqueue was
  lost) leaves `results_ai = Inconclusive`, not the model default.
- **Both engines:** Cortex and `ai_model` enabled, a mail case gets rows from both and waits for
  both; with `ai_model` the only other enabled analysis connector, disabling Cortex returns 409
  unless forced; disabling `ai_model` never returns 409.
- **Upgrade:** a pre-upgrade `provider-` row closed by the forwarding task produces the same case
  fields.
- Full backend suite (only the two known `google.api_core` errors); `backtest_scoring` identical.

## Left to the builder

Names of the new Celery task and helper functions; where `mark_ai_missing` lives inside `ai_model`;
how the forwarding task finds the row; whether `FetchResult.payload` and `StartResult.deferred` are
validated; the order of tasks in the plan.

## Calls made here, not decided with the owner

- The AI stays report-less (no `AnalyzerReport`), because adding reports would put AI rows into the
  report lists, the parsers and the per-case report API.
- A new data type `mail_archive` with value = case id, rather than reusing `file`.
- `general_purpose` as a class flag, not a manifest field, so third-party connectors need no change.
- The old task name stays for exactly one release.
- Delivery rows keep the event name `analyze`.
- `on_result` and `on_started` are called for deferred jobs only; the other paths do not call them
  until an engine needs it.
- A deferred job finishes even when its connector was disabled after the start (the engine rule),
  which changes today's "disabled provider fails at once" for the AI and one parity test.
- Disabling `ai_model` never needs `force`.
- All AI rules (marking the AI missing, the case-field write) live in `ai_model`; the engine layer
  stays AI-free.
