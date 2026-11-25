# Cortex as a connector: feasibility

Status: spike write-up, 2026-11-16. Nothing built. Read from the code on `main` at `db64b71f`.

## Verdict

Feasible, and worth doing in a reduced form.

- **Do:** put Cortex behind a generic "analysis engine" slot in the connector framework, so the
  backend talks to *an engine* and Cortex is the first one. About 250 lines of truly
  Cortex-specific code move; the rest stays where it is.
- **Do not:** move or rename the job ledger, the analyzer and report tables, or the reconcile
  step. They are already engine-neutral in behaviour, the connector framework itself depends on
  them, and renaming them means migrations on the largest tables for no functional gain.
- **The hard part is not Cortex.** It is that today's provider slot is shaped for one
  synchronous answer per case (the AI verdict). Cortex is many asynchronous jobs per case. The
  slot needs a second, asynchronous contract before Cortex can sit behind it.

## What Cortex does for the backend today

Five separate jobs, which the code currently treats as one thing:

| # | Job | Where | Cortex-specific? |
|---|---|---|---|
| 1 | Pick which analyzers run for an observable | `CortexJob.launch_cortex_jobs`, `get_file_analyzers`, `get_analyzers_by_type` | Half. The *policy* (YARA not on `.eml`, sandbox only on files, header analyzer excluded from by-type runs) is ours; the *catalog* comes from Cortex. |
| 2 | Start a job and record it | `CortexJob.run_analyzer`: `api.analyzers.run_by_name`, then an `AnalyzerReport` and a `CaseAnalyzerJob` row | The API call is. The two rows are not. |
| 3 | Learn that a job finished | `api/views/cortex_webhook.py` (shared-secret bearer, jobId dedup in cache) and the 300 s `update_ongoing_cases` fallback | Yes. |
| 4 | Fetch the result and store it | `CortexJobManager.update_single_job` → `get_job_from_api`, `get_report_from_api`, `update_report_instance` (copies `summary`, `summary.taxonomies`, `full`) | The fetch is. The stored shape is Cortex's report shape. |
| 5 | Keep the analyzer list in sync | `tasp/cron/sync_cortex.py`, task `sync_cortex` | Yes. |

Around those sit things that are **not** Cortex's job and should not move:

- **Ledger** `CaseAnalyzerJob`: "which jobs is this case waiting on". Reconcile, `fail_stale_jobs`
  and the `ai_model` provider all use it.
- **Reconcile** `reconcile_case_core`: the case state machine. Its only Cortex call is
  `mgr.update_single_job(caj)` for each pending row.
- **Scoring parsers** `score_process/scoring/cortex_analyzers/` (about 1,570 lines): map a stored
  report to a verdict. They read the database, never Cortex.
- **Derived observables** `derived_observables.py`: turns extractor output into new jobs. It
  calls `launch_cortex_jobs` once.

Size of the coupling: `cortex_job` is about 1,700 lines; roughly 40 non-test files in `api`,
`score_process`, `mail_feeder`, `tasp`, `url_process`, `connectors` and `ai_model` import from
it, almost all for the **models**, not for Cortex. About 100 test files mention Cortex.

Job starts are concentrated: `launch_cortex_jobs` is called from six places
(`tasp/tasks.py`, `mail_feeder/job_handler/artifacts/artifacts.py`,
`mail_feeder/job_handler/attachments/attachments.py`,
`mail_feeder/global_submission/gsubmission.py`, `api/views/url_analysis.py`,
`cortex_job/cortex_utils/derived_observables.py`).

## What we can leverage

Already in the tree, proven by the `ai_model` connector:

1. **The ledger already carries a non-Cortex engine.** `connectors/providers.py` writes
   `CaseAnalyzerJob` rows with a `provider-` id and no `AnalyzerReport`. Reconcile skips them
   (`update_single_job` returns when `analyzer_report is None`) and waits for the provider to
   close them. Two engines on one case work today.
2. **A provider task with the right failure behaviour.** `connectors.tasks.run_provider_analysis`:
   per-connector circuit breaker, retry only on retryable errors, a conditional UPDATE that
   claims the row so a redelivery is harmless, a `ConnectorDelivery` row per attempt, reconcile
   queued on commit.
3. **Config, secrets and UI for free.** A manifest's `config_schema` makes
   `integrations.<name>` a runtime-config section, overlays `secret` fields from Vault, validates
   URLs, and gives the connector the existing endpoints: state (enable/disable), config, test,
   deliveries. Cortex's `url`, `api_key` and `webhook_secret` fit this as they are.
4. **Schedules.** A manifest `Schedule` becomes a beat entry running `run_connector_sync`. The
   analyzer sync (job 5) and the fallback poll (job 3) map onto it directly.
5. **Breaker state and reset.** `common.http_client` already has a `cortex` breaker and, since
   the `ai_model` work, `breaker_state` and `request_reset`. Every registered connector gets a
   breaker, so Cortex would get the published state and the reset for nothing.
6. **Third-party engines.** The registry loads connectors from the `suspicious.connectors`
   entry-point group and isolates a broken one. An engine written outside this repository would
   load the same way.
7. **A parser registry keyed by analyzer name.** `AnalyzerParserRegistry.resolve` falls back to
   `DefaultTaxonomyParser`. A non-Cortex engine that stores a report with the same
   `summary.taxonomies` shape is scored with no new scoring code.
8. **A precedent for the cutover.** The AI analyzer left Cortex with old reports still parsed and
   kept out of the blend. The same "old rows keep working" rule applies here and is easier,
   because Cortex stays.

## What a connector cannot express today

1. **The contract is synchronous and single-answer.** `Connector.analyze(kind, case_id)` returns
   one `ProviderResult`, whose fields are the AI verdict (`score`, `confidence`, `category`,
   `model_version`, `assessment`, `shadow`). `finish_provider_analysis` writes `Case.results_ai`
   and an `AiAssessment`. None of that fits "start twelve jobs, hear back later".
2. **One provider per kind.** `enabled_provider` returns the single enabled connector and the
   state API refuses a second (`"<name> already provides <kind>"`). Right for the AI vote; wrong
   for engines, where Cortex plus a second engine on the same case is the point.
3. **No inbound path.** Connectors receive case events and run schedules. The Cortex webhook is
   a fixed view with its own secret in Django settings (`CORTEX_WEBHOOK_SECRET`).
4. **Off by default.** `enabled_by_default` is `False` unless the manifest says otherwise. An
   upgrade that leaves Cortex disabled stops all analysis. This is the `ai_model` upgrade trap
   again, with a larger blast radius.
5. **Engine-neutral names do not exist.** `cortex_job_id`, `analyzer_cortex_id`, the app label
   `cortex_job`, the settings key `integrations.cortex.analyzers.*`. Harmless, but any second
   engine stores its ids in a column named after Cortex. `ai_model` already does.

## Options

### A. Thin: Cortex as a connector for operations only

A `cortex` connector whose manifest carries the config schema, a `health_check`, and two
schedules (analyzer sync, fallback poll). Job starts, the webhook and reconcile do not change.

- **Gives:** Cortex in the Settings connectors list with a test button, Vault-backed secrets
  through the same path as the others, the sync and poll in the delivery ledger, breaker state
  and reset.
- **Does not give:** any way to run without Cortex or beside another engine.
- **Size:** small. One connector package, the two `tasp` tasks become schedules, config seeding.
- **Risk:** low. The only behaviour change is where two periodic tasks are registered.

### B. Engine slot: Cortex is the first analysis engine (recommended)

Add a second provider contract next to `analyze`, asynchronous and many-per-case:

```
engine.catalog()                      -> analyzers it offers, with data types
engine.start(analyzer, observable)    -> external job id, or None if refused
engine.fetch(job_id)                  -> status, and on success summary / taxonomies / full
```

- A new `connectors/engines.py` owns what `run_analyzer` and `update_single_job` do around the
  API call: write the `AnalyzerReport` and `CaseAnalyzerJob` rows, copy the result in, close the
  row. `connectors/contrib/cortex/` holds only the `cortex4py` calls.
- The six `launch_cortex_jobs` call sites call one `dispatch(observable, data_type, case)`, which
  applies our selection policy, then fans out to every enabled engine that offers a matching
  analyzer.
- Reconcile calls `engines.refresh(caj)` in place of `CortexJobManager().update_single_job(caj)`.
  The engine is found from the row's analyzer. Nothing else in reconcile changes.
- The webhook becomes `/api/connectors/<name>/webhook/`, with `/api/cortex/webhook/` kept as an
  alias so a deployed Cortex needs no reconfiguration.
- Several engines may be enabled at once. The one-per-kind rule stays for `mail_ai` only.
- Models, tables, column names, scoring parsers and the app label stay as they are.
- `enabled_by_default=True` for `cortex`, so an upgrade changes nothing.

- **Gives:** everything in A, plus the possibilities below.
- **Size:** medium. The moved code is about 250 lines; the work is in the call sites and in the
  tests that patch `CortexJob` by path.
- **Risk:** medium, concentrated in two places: the dispatch policy (mail and IOC roads select
  analyzers differently today) and report reuse across cases.

### C. Full extraction

B, plus rename `cortex_job` to an engine-neutral app, rename `cortex_job_id` and
`analyzer_cortex_id`, move the parsers out of `cortex_analyzers/`.

- **Gives:** tidy names.
- **Costs:** migrations on `AnalyzerReport` (it holds `report_full`, the largest table), about
  40 import sites, about 100 test files, an API and UI field rename.
- **Not recommended.** No behaviour depends on it. Revisit only if the names start causing
  mistakes.

## What B makes possible

Ordered by how directly the code supports it.

1. **Run without Cortex.** A deployment with only native engines needs no Cortex, no Cortex
   Elasticsearch use, and no Docker socket proxy for analyzer containers. That is the heaviest
   and most privileged part of the stack.
2. **Native engines for simple lookups.** VirusTotal, urlscan, a MISP lookup, CIRCL hashlookup:
   one HTTP call each. Through Cortex each costs a container start. A native engine returning
   the same taxonomy shape is scored by the existing parsers.
3. **Two engines on one case.** Cortex for sandbox and YARA, a native engine for lookups. The
   ledger already handles mixed rows.
4. **More than one Cortex.** A second instance (another network zone, or a sandbox-only one) as
   a second connector instance. Needs the connector to support named instances; the config
   schema already allows dotted keys.
5. **A fake engine for tests and the dev stack.** The full pipeline end to end with no Cortex
   container: faster CI, and a dev deployment that no longer needs the keystore and catalog
   steps in `init.sh`.
6. **One dispatch policy.** The six call sites collapse into one function. That closes the
   "mail and IOC roads select analyzers differently" flaw from the September audit, because the
   difference becomes one visible table.
7. **Operator visibility.** Every start and fetch in the delivery ledger with duration and
   error, where today a refused analyzer is a log line. Breaker state and reset in the UI.
8. **Per-analyzer shadowing.** Run a candidate engine or analyzer beside the live one and store
   its answer without scoring it, as `ai_model` does for a candidate model. Speculative: the
   shadow store today is specific to the AI assessment.
9. **Engines shipped separately.** An engine for a proprietary sandbox as its own package,
   through the entry-point group.

## Risks and things to prove first

- **Verdicts must not move.** `python manage.py backtest_scoring` byte-identical before and
  after, the rule already agreed for the IOC road. B touches no scoring code, so this should
  hold; it is the acceptance test.
- **Report reuse.** One `AnalyzerReport` can serve several cases (the ledger is a junction for
  that reason, and `analysis_done` counts reused results). The engine layer must keep that. Not
  read in detail for this write-up.
- **Webhook race.** A webhook can arrive before the launching transaction commits. Today the
  300 s poll covers it. Keep the poll.
- **Stale jobs.** Cortex leaves a job `InProgress` forever when it restarts mid-run;
  `fail_stale_jobs` is the only release. It works on the ledger, so it covers every engine, but
  the timeout (2 h, sized for a sandbox) becomes per engine.
- **The upgrade.** If the connector state row for `cortex` is created disabled, analysis stops
  silently. `enabled_by_default=True` plus a check in `make deploy`.
- **Config in three places.** `integrations.cortex` in `settings.json`, `CORTEX_WEBHOOK_SECRET`
  in Django settings, Cortex's own `application.conf`. The connector can own the first two. The
  third stays outside.
- **Tests patch by path.** Many tests patch `cortex_job.cortex_utils.cortex_and_job_management.CortexJob`.
  Leave a thin `CortexJob` shim that forwards to the engine layer until they are moved.

Not verified here: whether `suspicious` has a compose `depends_on` on Cortex (CLAUDE.md says it
comes up as a dependency; `compose_apps.yaml` showed only a shared network). `/api/health/`
reports Cortex as informational and returns 200 without it, so the backend already starts and
serves without Cortex.

## Suggested order

Each step ships alone and leaves the pipeline as it was.

1. **Option A.** The `cortex` connector with config, health and the two schedules. Proves the
   upgrade path and puts Cortex in the UI.
2. **Seam, no new engine.** `connectors/engines.py`, the contract, Cortex behind it, the six call
   sites on `dispatch`, reconcile on `refresh`. Backtest identical. Still exactly one engine.
3. **Fake engine** for tests and dev. This is what proves the seam is real.
4. **First native engine**, chosen by where container starts cost the most. Only now is the
   "several engines per case" rule exercised in production.

Stop after any step. Steps 1 and 2 have value without 3 and 4.

## Open questions

1. Is the goal to run without Cortex, to run beside it, or only to manage it like the other
   integrations? Option A answers the third alone.
2. Which lookups are worth a native engine? Needs the per-analyzer job counts and durations
   from production.
3. Does a deployment exist, or is one planned, where Cortex cannot be installed?
