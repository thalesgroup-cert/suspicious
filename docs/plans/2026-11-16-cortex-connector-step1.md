# Cortex connector, step 1 (operations only) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cortex appears and behaves as a connector (enabled, configured, tested, health-checked, analyzer sync scheduled), with a guard against disabling the last analysis connector, without changing how jobs are started or scored.

**Architecture:** A `cortex` connector in `connectors/contrib/cortex/` wraps the existing `sync_cortex_analyzers` and a status probe. A new provider kind `analysis` marks it and enables the last-engine guard on the state endpoint. `Analyzer` gains a `source` column naming the owning connector. Job starts, the webhook and reconcile are untouched (step 2).

**Tech Stack:** Django 5 / DRF, Celery beat, MariaDB migrations, React + MUI + Vitest.

**Spec:** `docs/specs/2026-11-16-analysis-engine-connectors-design.md` (step 1 of "Steps"; feasibility background in `2026-11-16-cortex-connector-feasibility.md`).

## Global Constraints

- `python manage.py backtest_scoring` output byte-identical before and after (record it on the base commit first, see Task 5).
- No migration on `AnalyzerReport`. The only migration is on `Analyzer`.
- Existing `settings.json` keeps working unchanged; the connector is named `cortex`, so its section is `integrations.cortex`.
- `/api/cortex/webhook/` and `CORTEX_WEBHOOK_SECRET` are not touched.
- The `mail_ai` slot keeps its one-enabled-per-kind rule; the `analysis` kind has none.
- Manifest: `name="cortex"`, `provides="analysis"`, `category="Analysis"`, `enabled_by_default=True`, one schedule `Schedule("sync", 60)` (today's `sync-cortex` interval).
- Guard: `PATCH /api/connectors/<name>/` with `enabled: false` on the last enabled `analysis` connector returns 409 unless the body has `"force": true` (boolean). A forced disable is logged at warning level with the user.
- Commits: Conventional Commits, explicit `git add <paths>`, no `git add -A`. Tests run through `ww test backend <label>` / `ww test frontend`.

## Review Focus

Most likely to bite, each pinned by a test in the owning task:

1. **Upgrade with no `ConnectorState` row for `cortex`:** it must read as enabled, not disabled (Task 3).
2. **Cortex not configured (default `url`, empty `api_key`):** `health_check` returns `ok=False` and never raises; the sync does not raise or write a delivery failure every minute (Task 3).
3. **Guard bypass:** `"force": "false"`, `"force": 1`, or `force` on an *enable* request must not skip or change the check; disabling an already-disabled connector is a no-op, not a 409 (Task 1).
4. **Double scheduling:** both the old `sync-cortex` beat entry and `connector-cortex-sync` present would run the sync twice (Task 3).
5. **Sync touching other sources:** `provider:` AI rows and any `source != "cortex"` rows must stay active when the sync deactivates missing analyzers (Task 2).

Known limit, stated so nobody is surprised: in this step the `enabled` flag gates only the sync and the connector UI. Job starts still go to Cortex whatever the flag says; gating them is step 2. The guard's message and the connector description say so.

---

### Task 1: The `analysis` provider kind and the last-engine guard

**Files:**
- Modify: `Suspicious/Suspicious/connectors/base.py` (kinds, near `PROVIDER_KIND_MAIL_AI`)
- Modify: `Suspicious/Suspicious/api/views/connectors.py` (`ConnectorStateView.patch`)
- Test: `Suspicious/Suspicious/api/tests/test_connectors_api.py` (follow its helper for registering a dummy connector; `connectors/tests/dummy.py` has the base dummy)

**Interfaces:**
- Produces: `PROVIDER_KIND_ANALYSIS = "analysis"` in `connectors.base`, included in `VALID_PROVIDER_KINDS`. 409 body `{"detail": str, "code": "last_analysis_connector"}`. Task 3 sets `provides` to it; Task 4 reads `code`.

- [ ] **Step 1: Write failing tests** in `test_connectors_api.py`, class `AnalysisGuardTests` (two dummy connectors providing `analysis`):
  - `test_disabling_the_only_enabled_analysis_connector_is_409`: status 409, `data["code"] == "last_analysis_connector"`, state still enabled.
  - `test_force_true_disables_it`: `{"enabled": false, "force": true}` returns 200, state disabled.
  - `test_disabling_one_of_two_needs_no_force`: 200.
  - `test_force_must_be_boolean_true`: `"force": "false"`, `"force": 1`, `"force": "true"` each give 409.
  - `test_disabling_an_already_disabled_connector_is_a_noop`: 200, no 409.
  - `test_enabling_an_analysis_connector_ignores_force_and_the_kind_cap`: enabling a second one returns 200 (the 409 "already provides" is for `mail_ai` only).
  - `test_a_plain_connector_is_never_guarded`: disabling a connector with `provides=""` needs no force.
- [ ] **Step 2: Run** `ww test backend api.tests.test_connectors_api` — expect the new tests FAIL.
- [ ] **Step 3: Implement.** Add the constant and extend `VALID_PROVIDER_KINDS`. In `patch`: apply the existing "already provides" 409 only when `kind != PROVIDER_KIND_ANALYSIS`; before saving a disable, when `kind == PROVIDER_KIND_ANALYSIS`, the connector is currently enabled, no other `analysis` connector is enabled, and `request.data.get("force") is not True`, return the 409 above. Message text: `"<name> is the last enabled analysis connector. Disabling it stops the analyzer sync and, once the engine layer ships, all new analysis. Send force to confirm."` When forced, `logger.warning` the connector name and `request.user`.
- [ ] **Step 4: Run** the same label — expect PASS; also `ww test backend connectors` for the registry tests.
- [ ] **Step 5: Commit** `feat(connectors): analysis provider kind and last-engine disable guard`.

### Task 2: `Analyzer.source`

**Files:**
- Modify: `Suspicious/Suspicious/cortex_job/models.py` (`Analyzer`)
- Create: `Suspicious/Suspicious/cortex_job/migrations/0017_analyzer_source.py`
- Modify: `Suspicious/Suspicious/tasp/cron/sync_cortex.py` (`sync_cortex_analyzers`)
- Modify: `Suspicious/Suspicious/connectors/providers.py` (`queue_provider_analysis` `get_or_create` defaults)
- Test: `Suspicious/Suspicious/cortex_job/tests/test_analyzer_source.py` (new, pattern of `test_backfill_migration.py` for the migration case); extend `Suspicious/Suspicious/tasp/tests/test_sync_cortex.py`

**Interfaces:**
- Produces: `Analyzer.source: CharField(max_length=100, default="cortex", db_index=True)`. Task 3's `sync` relies on the sync keeping non-`cortex` rows active.

- [ ] **Step 1: Write failing tests:**
  - `test_new_analyzer_defaults_to_cortex_source`.
  - `test_migration_marks_provider_rows_ai_model`: rows with `analyzer_cortex_id` starting `provider:`, and the row named by `ai_analyzer_name()`, become `ai_model`; all others `cortex`.
  - `test_sync_creates_rows_with_source_cortex` and `test_sync_deactivates_only_cortex_rows`: an `ai_model` row and a row with `source="other"` stay `is_active=True` when absent from the remote list; a `cortex` row absent from it goes inactive.
  - `test_sync_still_spares_the_configured_ai_analyzer_name` (the existing behaviour, kept).
  - `test_queue_provider_analysis_creates_the_row_with_source_ai_model`.
- [ ] **Step 2: Run** `ww test backend cortex_job.tests.test_analyzer_source tasp.tests.test_sync_cortex` — expect FAIL.
- [ ] **Step 3: Implement.** Add the field. Migration `0017`: `AddField` then `RunPython(mark_provider_rows, migrations.RunPython.noop)`. In `sync_cortex_analyzers` put `source="cortex"` in both `update_or_create` default dicts and add `.filter(source="cortex")` to the deactivation query, keeping the existing `exclude` of the AI name. In `queue_provider_analysis` add `"source": "ai_model"` to the create defaults.
- [ ] **Step 4: Run** the same labels plus `ww test backend connectors.tests.test_providers` — expect PASS.
- [ ] **Step 5: Commit** `feat(cortex_job): record which connector owns each analyzer`.

### Task 3: The `cortex` connector

**Files:**
- Create: `Suspicious/Suspicious/connectors/contrib/cortex/__init__.py`, `.../cortex/connector.py`
- Modify: `Suspicious/Suspicious/connectors/contrib/__init__.py` (`BUILTIN_CONNECTOR_PATHS`)
- Modify: `Suspicious/Suspicious/suspicious/settings.py` (remove the `"sync-cortex"` entry of `CELERY_BEAT_SCHEDULE`)
- Modify: `Suspicious/Suspicious/tasp/tasks.py` (`sync_cortex` body)
- Modify: `docs/components/backend/connectors.md` (add Cortex), `CHANGELOG.md`, `Suspicious/Suspicious/tasp/README.md` (the beat table row)
- Test: `Suspicious/Suspicious/connectors/tests/test_contrib_cortex.py` (new, style of `test_contrib_watcher.py`)

**Interfaces:**
- Consumes: Task 1 `PROVIDER_KIND_ANALYSIS`; Task 2 `sync_cortex_analyzers`.
- Produces: `class CortexConnector(Connector)` in `connectors.contrib.cortex.connector`; registered name `cortex`.

- [ ] **Step 1: Write failing tests** (`test_contrib_cortex.py`):
  - `test_manifest`: name, `provides == "analysis"`, `category == "Analysis"`, `enabled_by_default is True`, schedules `== (Schedule("sync", 60),)`, config keys exactly `url`, `api_key` (secret), `webhook_secret` (secret), `stale_job_timeout_seconds` (int, 7200), `analyzers.yara`, `analyzers.sandbox`, `analyzers.header`, `analyzers.file_info`, `analyzers.ai`; `url` and `api_key` required.
  - `test_registered_and_enabled_on_a_fresh_database`: `registry.names()` contains `cortex`; `get_state("cortex").enabled is True` with no prior row (Review Focus 1).
  - `test_health_ok_on_status_200` and `test_health_not_ok_on_connection_error`: patch `requests.get`; probe `GET {url}/api/status` with a 2 s timeout and no proxy, as `api/views/health.py::_check_cortex` does; `ok` when status `< 500`.
  - `test_health_unconfigured_returns_not_ok_without_raising`: default `url` `https://cortex.example.com` or empty `api_key` gives `ok=False`, detail names what is missing (Review Focus 2).
  - `test_sync_calls_sync_cortex_analyzers` (patch it) and `test_sync_when_unconfigured_does_nothing` (does not call it).
  - `test_beat_has_one_cortex_sync_entry`: `CELERY_BEAT_SCHEDULE` has no `"sync-cortex"`; after `registry.discover()` and the app's beat registration, `connector-cortex-sync` exists with `args == ["cortex"]` and schedule `60.0` (Review Focus 4).
  - `test_sync_cortex_task_runs_the_connector_sync`: `tasp.tasks.sync_cortex` still exists and calls `connectors.delivery.run_sync_now("cortex")`.
- [ ] **Step 2: Run** `ww test backend connectors.tests.test_contrib_cortex` — expect FAIL.
- [ ] **Step 3: Implement** `CortexConnector` after `WatcherConnector`'s shape. `health_check` reads `url` and `api_key` from `self.config`. `sync` returns without calling anything when unconfigured, else calls `sync_cortex_analyzers()`. The `description` says: syncs the Cortex analyzer catalogue every minute; job starts still go to Cortex whatever the enabled flag says. Add the path to `BUILTIN_CONNECTOR_PATHS`; delete the `sync-cortex` beat entry; make `tasp.tasks.sync_cortex` call `run_sync_now("cortex")` and keep its task name and `@shared_task` options.
- [ ] **Step 4: Run** `ww test backend connectors tasp api.tests.test_connectors_api`. Fix any test that counts or lists registered connectors; changing only its expectation, never the code under test.
- [ ] **Step 5: Docs**: one row in `connectors.md` (name, category, what it does, the limit above) and one CHANGELOG line.
- [ ] **Step 6: Commit** `feat(connectors): add the cortex connector (config, health, analyzer sync)`.

### Task 4: Settings UI confirmation

**Files:**
- Modify: `suspicious-ui/src/features/settings/components/connectors.ts` (`setConnectorEnabled`)
- Modify: `suspicious-ui/src/features/settings/components/ConnectorTile.tsx` (the toggle mutation at line ~56)
- Test: `suspicious-ui/src/features/settings/components/__tests__/connectors.test.tsx`, `ConnectorTile.test.tsx`

**Interfaces:**
- Consumes: Task 1's 409 body `{detail, code: "last_analysis_connector"}`.
- Produces: `setConnectorEnabled(name: string, enabled: boolean, force?: boolean)`; sends `{ enabled, force: true }` only when `force` is true.

- [ ] **Step 1: Write failing tests:** `setConnectorEnabled` sends no `force` key by default and `force: true` when asked; in `ConnectorTile.test.tsx`, a 409 with that `code` opens a confirmation showing `detail`, cancelling sends no second request and leaves the toggle off, confirming resends with `force: true`; a 409 with any other code shows the normal error.
- [ ] **Step 2: Run** `ww test frontend` — expect the new tests FAIL.
- [ ] **Step 3: Implement.** In `ConnectorTile`, catch the Axios 409 with that `code`, ask with the same confirmation dialog component `ConnectorsPanel.tsx` already uses, then call the mutation again with `force: true`. No new component.
- [ ] **Step 4: Run** `ww test frontend` and the frontend lint — expect PASS and clean.
- [ ] **Step 5: Commit** `feat(ui): confirm before disabling the last analysis connector`.

### Task 5: Upgrade and verdict checks

**Files:**
- Test: `Suspicious/Suspicious/connectors/tests/test_contrib_cortex.py` (add `UpgradeTests`)

- [ ] **Step 1: Before any task's code lands**, on the base commit record `ww stack backtest suspicious` output to `docs/plans/.evidence/cortex-step1-backtest-before.txt` (git-ignored, not committed).
- [ ] **Step 2: Write `UpgradeTests`:** with `integrations.cortex` set exactly as in `docs/getting-started/examples/Suspicious-settings.example.json`, `registry.instantiate("cortex").config` (with a non-empty `api_key`: the example ships it empty, which reads as `partial`, since `api_key` is required) carries `url`, `api_key` and the five `analyzers.*` names; `_serialize_connector("cortex")["status"] == "connected"`; `GET /api/connectors/` lists `cortex` enabled.
- [ ] **Step 3: Run** the full suite `ww test backend`; expect only the known GCS import errors if the image lacks `google-cloud-storage`, and say so.
- [ ] **Step 4: Run** the backtest again and `diff` against step 1's file; expected: no difference.
- [ ] **Step 5: Commit** `test(connectors): cover the cortex connector upgrade path`.

## Self-Review

- **Spec coverage:** manifest, config schema, health, schedule, `Analyzer.source` (migration backfill, sync scoping, AI row), `analysis` kind with no one-per-kind cap, the guard with `force`, the warning log, UI confirmation, upgrade test, backtest identical. Not in this step by design: `engines.py`, the contract operations, webhook route, `fail_stale_jobs` per engine, delivery rows for failed starts.
- **Deviation from the spec text:** the guard message does not claim new cases get no analysis, because in step 1 they still do; the spec's wording applies from step 2. The message keeps the spec's intent and names the sync.
- **Name consistency:** `PROVIDER_KIND_ANALYSIS`, `last_analysis_connector`, `CortexConnector`, `Analyzer.source`, `setConnectorEnabled(name, enabled, force?)` are used the same way in every task.

## Amendments after the first audit and the cloud review

Built, and tested, beyond the tasks above:

- The sync refuses an analyzer name another source owns (spec: refused, not merged).
- `sync_cortex_analyzers(strict=True)` re-raises a fetch failure, so a failed sync is a failed
  delivery and is retried; in strict mode it skips its own use of the `cortex` breaker, because
  `run_sync_now` already runs the sync under it.
- `run_sync_now` logs a successful sync at most once an hour (and the first success after a
  failure); a 60 s sync would otherwise add about 1,400 ledger rows a day.
- Health probes `GET /api/analyzer` with the key, lists roles Cortex does not offer, and reports
  inactive analyzers, jobs pending over 30 minutes and the age of the last webhook.
- The webhook reads `webhook_secret` from the connector config (setting as fallback).
- Toggling a connector locks that kind's state rows so the last-engine guard cannot race.
