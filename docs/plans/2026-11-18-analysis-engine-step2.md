# Analysis engine layer, step 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The pipeline starts, fetches and receives callbacks for analysis jobs through enabled `analysis` connectors, with Cortex as the first one, and finalises cases with no change in verdicts.

**Architecture:** Connectors implement `catalog`, `start`, `fetch` and optional `webhook`. A new `connectors/engines.py` is the only code the pipeline calls (`dispatch`, `refresh`, `handle_webhook`, `sync_catalog`); it alone writes `AnalyzerReport` and `CaseAnalyzerJob`. Cortex's `cortex4py` calls move into the Cortex connector. The `CortexJob` and `CortexJobManager` classes stay as thin forwarders until their tests move.

**Tech Stack:** Django 5 / DRF, Celery, cortex4py, pybreaker.

**Spec:** `docs/specs/2026-11-16-analysis-engine-connectors-design.md` (section "Design", step 2 of "Steps"). Builds on branch `feat/cortex-connector-step1`.

## Global Constraints

- `backtest_scoring` output identical before and after, compose and log lines filtered (baseline recorded on the base commit before Task 1; method in `.superpowers/sdd/2026-11-16-cortex-connector-step1/progress.md`).
- No migration. No change under `score_process/` or to `reconcile_case_core`'s state machine, `finalise`, derived observables or the `case_finalised` event.
- `settings.json` unchanged. Roles stay under `integrations.cortex.analyzers.{yara,sandbox,header,file_info,ai}`.
- `/api/cortex/webhook/` keeps its status codes, bodies, Bearer scheme and 1 h jobId dedup; `CORTEX_WEBHOOK_SECRET` stays readable as the fallback it is today.
- Selection policy (one function, `connectors.engines.select_analyzers`): `mail_body` → only the `yara` role; `mail_header` → only the `header` role; `file` → roles `yara`, `file_info`, `sandbox`, and for an `.eml` file none of `ai`, `yara`, `sandbox`, `header`; anything else → every analyzer offered for the type minus roles `yara`, `sandbox`, `header`. A role absent from config must never put `None` or `{}` into a set (an earlier bug).
- Ids: Cortex keeps raw ids in `Analyzer.analyzer_cortex_id` and `CaseAnalyzerJob.cortex_job_id`; any other engine stores `"<connector>:<id>"` and `"<connector>-<id>"`, within 50 characters.
- A disabled engine starts nothing but its pending jobs are still fetched. No engine enabled: `dispatch` writes no rows.
- Only a failed `start` is written to `ConnectorDelivery` (event `"start"`, the analyzer name in `error`).
- The webhook is accepted while the connector is disabled.
- Commits: Conventional Commits, explicit `git add <paths>`, no `Co-Authored-By` trailer. Tests via `ww test backend <label>` from the worktree.

## Review Focus

1. **Row parity:** `dispatch` through Cortex writes the same `AnalyzerReport` and `CaseAnalyzerJob` field values that `CortexJob.run_analyzer` writes today (status `InProgress`, level `info`, placeholder `report_*`, `tlp` 2, `mail_body` sent as `file`) (Task 3).
2. **`fetch` outcomes:** a network error or open breaker is `unknown` and must leave the row untouched; only a confirmed 404 is `gone` and becomes `Deleted` (Tasks 2, 4).
3. **Disabled engine, in-flight job:** still fetched, case still finalises (Task 4).
4. **Failure isolation:** one engine raising, or refusing one analyzer, must not stop the other engines or the other analyzers (Task 3).
5. **Webhook parity:** wrong secret 401 on both routes, unknown or non-analysis connector 404, duplicate jobId dedup, accepted while disabled (Task 5).
6. **Name clash:** a second engine offering an `Analyzer.name` owned by another source is refused and logged, never started (Tasks 3, 7).

---

### Task 1: The contract types and connector hooks

**Files:**
- Modify: `Suspicious/Suspicious/connectors/base.py`
- Test: `Suspicious/Suspicious/connectors/tests/test_base.py`

**Interfaces:**
- Produces, all in `connectors.base`:
  - `@dataclass(frozen=True) CatalogEntry(id: str, name: str, data_types: tuple[str, ...])`
  - `@dataclass(frozen=True) FetchResult(state: str, status: str = "", summary: dict | None = None, full: dict | None = None)`; `state` is one of `FETCH_RESULT`, `FETCH_GONE`, `FETCH_UNKNOWN` (module constants `"result"`, `"gone"`, `"unknown"`); `status` is `Waiting|InProgress|Success|Failure` when `state == "result"`.
  - `@dataclass(frozen=True) StartResult(job_id: str, finished: FetchResult | None = None)`
  - On `Connector`: `catalog(self, data_type: str | None = None, name: str | None = None) -> list[CatalogEntry]`, `start(self, analyzer: CatalogEntry, data_type: str, value: str) -> StartResult | None` (`None` = refused), `fetch(self, job_id: str) -> FetchResult`, `webhook(self, headers: dict, payload: dict) -> list[str] | None` (job ids announced; `None` = rejected as unauthenticated). Defaults raise `NotImplementedError`.

- [ ] **Step 1: Write failing tests** in `test_base.py`: the three dataclasses are frozen and equal by value; `FetchResult("result", "Success", {"a": 1}, {"b": 2})` keeps its fields; the four constants exist; a bare `Connector` subclass raises `NotImplementedError` from each new hook.
- [ ] **Step 2: Run** `ww test backend connectors.tests.test_base` — expect FAIL.
- [ ] **Step 3: Implement** the types and hooks exactly as in Interfaces.
- [ ] **Step 4: Run** the same label plus `connectors` — expect PASS.
- [ ] **Step 5: Commit** `feat(connectors): analysis engine contract types and hooks`.

### Task 2: Cortex connector operations

**Files:**
- Modify: `Suspicious/Suspicious/connectors/contrib/cortex/connector.py`
- Test: `Suspicious/Suspicious/connectors/tests/test_contrib_cortex_ops.py` (new)

**Interfaces:**
- Consumes: Task 1 types; `cortex_job.cortex_utils.session_cortex_api.SessionCortexApi` (patch point in tests).
- Produces on `CortexConnector`:
  - `catalog`: by `data_type` uses `api.analyzers.get_by_type`; by `name` uses `api.analyzers.get_by_name`; neither uses `GET analyzer?range=all` (the workaround in `tasp/cron/sync_cortex.py`). Returns `CatalogEntry(id=analyzer.id, name=analyzer.name, data_types=tuple(analyzer.dataTypeList))`; a lookup that fails returns `[]`.
  - `start`: `api.analyzers.run_by_name(analyzer.name, {"data": value, "dataType": "file" if data_type == "mail_body" else data_type, "tlp": 2})`; returns `StartResult(job_id=report.id)`, or `None` when Cortex rejects the input or returns nothing. Empty or blank `value` returns `None` without calling Cortex.
  - `fetch`: job via `api.jobs.get_by_id`, report via `api.jobs.get_report`, both under the `cortex` breaker with `common.http_client.RETRY` as today; `NotFoundError` → `FetchResult("gone")`; any other error or `CircuitBreakerError` → `FetchResult("unknown")`; otherwise `FetchResult("result", job.status, report["summary"], report["full"])`. `job.dataType` must be returned in `FetchResult.summary` untouched; the engine layer checks it (Task 4).
  - `webhook`: `Authorization: Bearer <webhook_secret>` compared with `hmac.compare_digest`; secret from `self.config["webhook_secret"]`, falling back to `django.conf.settings.CORTEX_WEBHOOK_SECRET`; `None` when absent or wrong; else `[str(payload.get("jobId") or payload.get("job_id") or "").strip()]` or `[]` when empty.
- The client is built from `self.config["url"]` and `["api_key"]` with no proxies, trailing slash trimmed.

- [ ] **Step 1: Write failing tests** with `SessionCortexApi` patched: catalog by type and by name, and `[]` on error; `start` payload for `file` and for `mail_body` (sent as `file`), `None` for blank value and for a raising `run_by_name`; `fetch` returns `result`, `gone` (on `NotFoundError`), `unknown` (on `ConnectionError`, on `CircuitBreakerError`); `webhook` returns the id for the right secret, `None` for a wrong or missing one, `[]` for a missing `jobId`, accepts `job_id`.
- [ ] **Step 2: Run** `ww test backend connectors.tests.test_contrib_cortex_ops` — expect FAIL.
- [ ] **Step 3: Implement** the four operations by moving the `cortex4py` calls out of `cortex_and_job_management.py` (keep those originals until Tasks 3 and 4 switch over; do not delete anything yet).
- [ ] **Step 4: Run** the label plus `connectors.tests.test_contrib_cortex` — expect PASS.
- [ ] **Step 5: Commit** `feat(cortex): catalog, start, fetch and webhook operations on the connector`.

### Task 3: `engines.dispatch` and the selection policy

**Files:**
- Create: `Suspicious/Suspicious/connectors/engines.py`
- Modify: `Suspicious/Suspicious/cortex_job/cortex_utils/cortex_and_job_management.py` (`CortexJob.launch_cortex_jobs` forwards)
- Test: `Suspicious/Suspicious/connectors/tests/test_engines_dispatch.py` (new); `cortex_job/tests/test_run_analyzer_writes_caj.py` must pass unchanged

**Interfaces:**
- Consumes: Tasks 1-2; `CortexJob.get_data_value`, `set_analyzer_report_data`, `get_analyzer_db` (call them in place; they are already generic apart from `get_analyzer_db`, which takes an object with `.id`, `.name`).
- Produces in `connectors.engines`:
  - `enabled_engines() -> list[str]`: names of connectors providing `analysis` that are enabled, sorted.
  - `select_analyzers(data_type: str, value, offered: list[CatalogEntry], roles: dict) -> list[CatalogEntry]`: the Global Constraints policy, pure.
  - `dispatch(value, data_type: str, case) -> list[str]`: for each enabled engine: `catalog()`, `select_analyzers`, drop entries whose `Analyzer.name` is owned by another source (log an error), `start`, then write the rows in one `transaction.atomic` exactly as `CortexJob.run_analyzer` does; returns the ledger job ids. A finished `StartResult` stores the result and closes the row (Task 4's `apply_result`, import lazily). Per-engine and per-analyzer failures are logged; a failed `start` also writes `ConnectorDelivery(connector, event="start", case_id, status="failed", error=<analyzer name>: <reason>)`.
  - `ledger_ids(connector: str, ext_job_id: str, ext_analyzer_id: str) -> tuple[str, str]`: raw for `cortex`, namespaced otherwise (Global Constraints).
- `CortexJob.launch_cortex_jobs(self, value, data_type, case)` becomes `return engines.dispatch(value, data_type, case)`; `CortexJob.__init__` no longer builds an API client.

- [ ] **Step 1: Write failing tests.** (a) `select_analyzers`: one test per data type in the policy, including `.eml` file, absent roles, and `mail_header` with no `header` role giving `[]`. (b) Row parity: with a fake engine connector registered, `dispatch(url_obj, "url", case)` writes one `AnalyzerReport` (status `InProgress`, level `info`, confidence 0, score 0, `report_summary == {"ongoing": "analysis"}`) and one `CaseAnalyzerJob` (`InProgress`), same fields as `run_analyzer` — assert against a `run_analyzer` call on the same input. (c) Two fake engines both contribute a row to one case; one raising does not stop the other (Review Focus 4); a refusing `start` writes no row. (d) A disabled engine starts nothing; no engine enabled returns `[]` and writes nothing. (e) A name owned by `source="cortex"` offered by a second engine is skipped and logged (Review Focus 6). (f) A failed `start` writes the `ConnectorDelivery` row. (g) `ledger_ids` for `cortex` and for `"fake"`, within 50 characters.
- [ ] **Step 2: Run** `ww test backend connectors.tests.test_engines_dispatch` — expect FAIL.
- [ ] **Step 3: Implement** `connectors/engines.py` and the forwarder. Port the policy from `launch_cortex_jobs`, `get_file_analyzers` and `get_analyzers_by_type` verbatim in effect; the roles dict is `get_section("integrations.cortex")["analyzers"]` read once per call.
- [ ] **Step 4: Run** the label, `cortex_job`, `mail_feeder`, `tasp` and `api.tests.test_url_analysis` (the existing tests that patch `CortexJob` keep passing) — expect PASS.
- [ ] **Step 5: Commit** `feat(connectors): engines.dispatch and the shared analyzer selection policy`.

### Task 4: `engines.refresh` and reconcile

**Files:**
- Modify: `Suspicious/Suspicious/connectors/engines.py`, `Suspicious/Suspicious/cortex_job/cortex_utils/reconciliation.py` (the `mgr.update_single_job(caj)` line), `Suspicious/Suspicious/cortex_job/cortex_utils/cortex_and_job_management.py` (`CortexJobManager.update_single_job` forwards)
- Test: `Suspicious/Suspicious/connectors/tests/test_engines_refresh.py` (new); `cortex_job/tests/test_legacy.py`, `test_stale_job_clock.py`, `connectors/tests/test_provider_dispatch.py` must pass unchanged

**Interfaces:**
- Consumes: Tasks 1-3.
- Produces in `connectors.engines`:
  - `refresh(caj: CaseAnalyzerJob, cache: dict | None = None) -> None`: skip rows with no `analyzer_report`; engine = `registry.instantiate(caj.analyzer.source)` (skip with a warning when that connector is not registered); `fetch(caj.cortex_job_id)` once per job id per `cache`; then the logic of `CortexJobManager.get_cortex_jobs_results` and `update_single_job`, unchanged in effect: `gone` → report `Deleted`; `unknown` → no change; `result` with a matching data type (`job.dataType == report.type`, or `mail_body` vs `file`) → `update_report_instance`; `Success` → score the report through `CortexAnalyzerReports.create_and_save_report`; row status mirrors the report, `completed_at` set when it leaves the pending states; a pending report older than the engine's `stale_job_timeout_seconds` (config, default 7200) becomes `Failure`.
  - `apply_result(report_instance, result: FetchResult) -> list[str]`: the `update_report_instance` body, engine-neutral (changed field names).
- `reconcile_case_core` calls `engines.refresh(caj, cache)` with one cache per call. Cached job and report state no longer lives on the class.

- [ ] **Step 1: Write failing tests** with a fake engine: success writes summary, taxonomy and full and scores; `unknown` leaves status and timestamps untouched (Review Focus 2); `gone` sets `Deleted`; a data-type mismatch writes nothing; a disabled engine's pending row is still refreshed and the case finalises (Review Focus 3); a pending row past the engine's timeout becomes `Failure`; one fetch per job id when two cases share it; a `provider-` row (no report) is skipped.
- [ ] **Step 2: Run** `ww test backend connectors.tests.test_engines_refresh` — expect FAIL.
- [ ] **Step 3: Implement** by moving the logic out of `CortexJobManager`; the manager's methods become forwarders.
- [ ] **Step 4: Run** the label, `cortex_job`, `connectors`, `tasp.tests.test_reconcile_task` — expect PASS.
- [ ] **Step 5: Commit** `feat(connectors): engines.refresh drives reconcile through the connector`.

### Task 5: The generic webhook route

**Files:**
- Modify: `Suspicious/Suspicious/connectors/engines.py`, `Suspicious/Suspicious/api/views/cortex_webhook.py`, `Suspicious/Suspicious/api/urls.py`
- Test: `Suspicious/Suspicious/api/tests/test_connector_webhook.py` (new); `api/tests/test_cortex_webhook.py` must pass unchanged

**Interfaces:**
- Consumes: Task 2 `Connector.webhook`.
- Produces: `engines.handle_webhook(connector_name: str, headers, payload) -> tuple[int, dict]` returning the status and body the Cortex view returns today for every case (503 unconfigured, 401, 400 missing id, 200 duplicate, 202 queued, 202 no pending case). View `ConnectorWebhookView` at `POST /api/connectors/<str:name>/webhook/` (no auth classes, no throttle): 404 for an unknown connector, one not providing `analysis`, or `NotImplementedError` from `webhook`. `CortexWebhookView` becomes a call to the same handler with `"cortex"`. The 1 h jobId dedup and the `cortex_last_webhook_at` cache write move into the handler.

- [ ] **Step 1: Write failing tests:** the nine cases of `test_cortex_webhook.py` against `/api/connectors/cortex/webhook/` with identical expectations; 404 for `/api/connectors/nope/webhook/` and for a connector that does not provide `analysis`; accepted while `cortex` is disabled; a fake engine's webhook reaches `reconcile_case.delay` for its own pending rows only.
- [ ] **Step 2: Run** `ww test backend api.tests.test_connector_webhook` — expect FAIL.
- [ ] **Step 3: Implement** the handler and both views.
- [ ] **Step 4: Run** the label plus `api.tests.test_cortex_webhook` — expect PASS.
- [ ] **Step 5: Commit** `feat(api): generic connector webhook route, cortex route forwards to it`.

### Task 6: Repoint the six call sites

**Files (non-test):** `tasp/tasks.py` (`dispatch_case_analysis`), `mail_feeder/job_handler/artifacts/artifacts.py`, `mail_feeder/job_handler/attachments/attachments.py`, `mail_feeder/global_submission/gsubmission.py`, `api/views/url_analysis.py`, `cortex_job/cortex_utils/derived_observables.py`. **Tests:** the 16 files that patch `…CortexJob` at those module paths.

**Interfaces:** each site calls `connectors.engines.dispatch(value, data_type, case)` in place of `CortexJob().launch_cortex_jobs(value=…, data_type=…, case=…)`. Tests patch `<module>.dispatch` (imported into the module as `dispatch`) instead of `<module>.CortexJob`; asserted call arguments stay the same.

- [ ] **Step 1: Change the tests first** to patch `dispatch` at each module path; run them — expect FAIL (still importing `CortexJob`).
- [ ] **Step 2: Change the six sites.** Mechanical: one import, one call. No other edit.
- [ ] **Step 3: Run** `ww test backend tasp mail_feeder api cortex_job` — expect PASS.
- [ ] **Step 4: Commit** `refactor: start analysis jobs through engines.dispatch`.

### Task 7: `engines.sync_catalog`

**Files:**
- Modify: `Suspicious/Suspicious/connectors/engines.py`, `Suspicious/Suspicious/connectors/contrib/cortex/connector.py` (`sync`), `Suspicious/Suspicious/tasp/cron/sync_cortex.py`
- Test: `Suspicious/Suspicious/connectors/tests/test_engines_sync.py` (new); `tasp/tests/test_sync_cortex.py` must pass unchanged

**Interfaces:** `sync_catalog(connector_name: str) -> int`: calls `connector.catalog()` with no filter (Cortex lists everything via `GET analyzer?range=all`; add that path to `CortexConnector.catalog` when both filters are `None`), upserts `Analyzer` rows with `source=connector_name` using `ledger_ids`, skips names owned by another source with an error log, deactivates only that source's rows absent from the catalog (sparing `ai_analyzer_name()` as today), then runs the configured-roles check. `sync_cortex_analyzers(config_path=..., strict=False)` keeps its signature and calls the same code.

- [ ] **Step 1: Write failing tests:** a fake engine's catalog creates `source="fake"` rows with namespaced ids; absent names deactivate only that source; a name owned by `cortex` is skipped; `strict=True` re-raises a fetch failure, `AuthenticationError` carries `retryable = False`.
- [ ] **Step 2: Run** `ww test backend connectors.tests.test_engines_sync` — expect FAIL.
- [ ] **Step 3: Implement**, moving the body of `sync_cortex_analyzers` into the engine layer.
- [ ] **Step 4: Run** the label, `tasp.tests.test_sync_cortex`, `connectors.tests.test_contrib_cortex` — expect PASS.
- [ ] **Step 5: Commit** `refactor(connectors): analyzer catalogue sync through the engine layer`.

### Task 8: Per-engine stale timeout, wording, docs, acceptance

**Files:**
- Modify: `Suspicious/Suspicious/tasp/tasks.py` (`fail_stale_jobs`), `Suspicious/Suspicious/connectors/contrib/cortex/connector.py` (description), `Suspicious/Suspicious/api/views/connectors.py` (guard message), `docs/components/backend/connectors.md`, `CHANGELOG.md`, `CLAUDE.md` (the Cortex lines)
- Test: `Suspicious/Suspicious/tasp/tests/test_fail_stale_jobs.py`, `connectors/tests/test_contrib_cortex.py`, `api/tests/test_connectors_api.py`

**Interfaces:** `fail_stale_jobs` applies each row's engine timeout (`stale_job_timeout_seconds` from that connector's config, 7200 when absent or the connector is unregistered). The Cortex description no longer says job starts ignore the flag; the guard message says disabling stops all new analysis from that connector and asks "Disable it anyway?". The docs drop the "stored but unused" note for `stale_job_timeout_seconds`.

- [ ] **Step 1: Write failing tests:** two stale rows from two engines with different timeouts, only the older-than-its-own-timeout one fails; the description and guard texts.
- [ ] **Step 2: Run** `ww test backend tasp.tests.test_fail_stale_jobs connectors.tests.test_contrib_cortex api.tests.test_connectors_api` — expect FAIL.
- [ ] **Step 3: Implement** the three changes and the docs.
- [ ] **Step 4: Acceptance, recorded in the ledger:** full `ww test backend` (only the known `google.api_core` errors tolerated); `backtest_scoring` run on this branch diffed against the baseline; with `cortex` disabled and a fake engine enabled in a test, a mail case and a URL case finalise from the fake engine's results; with both enabled, one case holds rows from both and waits for both.
- [ ] **Step 5: Commit** `feat(connectors): per-engine stale timeout, wording and docs for the engine layer`.

## Self-Review

- **Spec coverage:** contract and hooks (T1), Cortex operations and webhook auth (T2), `dispatch`, selection policy, id namespacing, source ownership and name clash, failed-start delivery rows (T3), `refresh`, three fetch outcomes, disabled-engine fetching, per-engine stale timeout (T4, T8), generic route and the old route as a forwarder (T5), the six call sites (T6), `sync_catalog` (T7), wording and docs (T8). Not here by design: the test engine in tree (step 3), the mail AI on the contract (step 4), removing the `CortexJob` and `CortexJobManager` forwarders.
- **Names used across tasks:** `CatalogEntry`, `FetchResult`, `StartResult`, `FETCH_RESULT|GONE|UNKNOWN`, `enabled_engines`, `select_analyzers`, `dispatch`, `ledger_ids`, `refresh`, `apply_result`, `handle_webhook`, `sync_catalog` are spelled identically everywhere.
- **Risk concentration:** Task 3 (selection policy parity) and Task 4 (fetch outcomes) carry the verdict risk; each pins its Review Focus lines with a test before the code moves.
