# The mail AI verdict as an analysis engine (step 4) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `ai_model` produces the mail AI verdict as an ordinary analysis-engine job (deferred mode), and the `mail_ai` provider slot is removed, with the same verdicts as today.

**Architecture:** The engine contract gains a deferred mode (`StartResult.deferred`, `Connector.run`, `FetchResult.payload`) and two hooks (`on_started`, `on_result`). `engines.dispatch` registers a report-less ledger row and queues `run_engine_job`, which replaces `run_provider_analysis` and applies the retry, breaker and claim rules of today. All AI rules (case AI fields, `AiAssessment`, "AI missing") live in `ai_model`.

**Tech Stack:** Django 5 / DRF, Celery, the connector framework from steps 1-3.

**Spec:** `docs/specs/2026-11-19-mail-ai-as-engine-design.md` (read it: it is the authority). Builds on branch `feat/fixture-analysis-engine`.

## Global Constraints

- No migration; nothing under `score_process/`; `settings.json` unchanged; the AI vote's analyzer name stays `ai_analyzer_name()` (`integrations.cortex.analyzers.ai`, default `AI_Mail_Analyzer`); `ai_model` keeps its connector name and config.
- `backtest_scoring` identical to a baseline taken before Task 1 (it does not cover this path: the parity tests are the real check).
- Retry and breaker behaviour equals today's: only a retryable `ProviderUnavailable` is retried, twice, with `5 * 2**n + uniform(0, 3)` seconds of delay; any other error fails the row at once; every call to the connector runs under that connector's breaker (`common.http_client.get_breaker(name).calling()`); the row is claimed with a conditional UPDATE on pending statuses so a redelivery or `fail_stale_jobs` cannot double-close it.
- The engine layer (`connectors/engines.py`, `connectors/tasks.py`, `connectors/base.py`) must not import or name anything from `ai_model`.
- A deferred job runs even if its connector was disabled after the start.
- `ConnectorDelivery` rows of deferred jobs use `event="analyze"`, status `success`/`failed`, the error text on failure.
- New ledger ids come from `engines.ledger_ids(connector, ext_job_id, ext_analyzer_id)` (job id `ai_model-<hex>`, within 50 characters); rows open at upgrade keep the `provider-` prefix.
- Commits: Conventional Commits, subject at most 72 characters, explicit `git add <paths>`, no `Co-Authored-By`. Tests via `ww test backend <label>` from the worktree.

## Review Focus

1. **AI missing on every dead end:** a deferred row closed by `fail_stale_jobs`, a lost enqueue and a dead worker must all leave `results_ai = Inconclusive` (never the model default "Suspicious"): pinned by `on_started` marking at registration unless the case already has an assessment (Task 3).
2. **Refusals are failures:** no archive, unreadable archive, a server refusal ("can't tell") and an answer with no model version close the row `Failure`, write a `failed` delivery row and mark the AI missing unless an earlier assessment exists; a normal answer, even an INCONCLUSIVE class with a model version, is `Success` (Task 3).
3. **Idempotence:** redelivery of the Celery task after the row closed does nothing; two workers racing close it once; the retried `run` after a retryable error does not duplicate `AiAssessment` or deliveries (Task 2).
4. **Guard semantics:** with `ai_model` and Cortex enabled, disabling Cortex is 409 unless forced only when no other general-purpose engine remains; disabling `ai_model` never needs `force` (Task 3).
5. **Upgrade:** a `provider-` row opened by the old code before the upgrade, run by the forwarding task, produces the same case fields as the old path (Task 4).
6. **Engine layer stays AI-free:** a grep test proves `connectors/engines.py`, `connectors/tasks.py`, `connectors/base.py` contain no `ai_model`, `AiAssessment`, `results_ai` (Task 4).

---

### Task 1: Contract additions

**Files:**
- Modify: `Suspicious/Suspicious/connectors/base.py`
- Test: `Suspicious/Suspicious/connectors/tests/test_base.py`

**Interfaces:**
- Produces in `connectors.base`: `DATA_TYPE_MAIL_ARCHIVE = "mail_archive"`; `StartResult.deferred: bool = False` (added field, default keeps all callers working); `FetchResult.payload: dict | None = None` (added field after `data_type`); on `Connector`: `general_purpose: ClassVar[bool] = True`; `run(self, job_id: str, data_type: str, value: str) -> FetchResult` (default raises `NotImplementedError`); `on_started(self, case, analyzer_name: str) -> None` and `on_result(self, case, analyzer_name: str, result: FetchResult) -> None` (defaults do nothing).

- [ ] **Step 1: Write failing tests**: the constant value; the two new fields' defaults and that `FetchResult("result","Success")` and `StartResult("j")` still construct; a bare `Connector` subclass: `general_purpose is True`, `run` raises `NotImplementedError`, both hooks return `None` without error.
- [ ] **Step 2: Run** `ww test backend connectors.tests.test_base` — expect FAIL.
- [ ] **Step 3: Implement** exactly the Interfaces.
- [ ] **Step 4: Run** the label plus `connectors` — expect PASS.
- [ ] **Step 5: Commit** `feat(connectors): deferred jobs and result hooks in the engine contract`.

### Task 2: Deferred mode in the engine layer

**Files:**
- Modify: `Suspicious/Suspicious/connectors/engines.py` (`_start`, selection policy, `get_data_value` use), `Suspicious/Suspicious/cortex_job/cortex_utils/cortex_and_job_management.py` (`CortexJob.get_data_value`), `Suspicious/Suspicious/connectors/tasks.py`
- Test: `Suspicious/Suspicious/connectors/tests/test_engines_deferred.py` (new)

**Interfaces:**
- Consumes: Task 1 types; `engines.ledger_ids`, `engines.dispatch`; `connectors.providers.ProviderUnavailable`.
- Produces: selection policy for `mail_archive`: only the analyzer in the `ai` role, offered through `catalog(name=<ai role name>)` (like the other role-driven types); `CortexJob.get_data_value(case, "mail_archive")` returns `str(case.id)`. In `_start`, a `StartResult` with `deferred=True` writes a `CaseAnalyzerJob` row (`InProgress`, `analyzer_report=None`, ledger id from `ledger_ids`), calls `connector.on_started(case, entry.name)` in the same transaction (an exception from it is logged with the class name and does not undo the row), and enqueues `run_engine_job.delay(row.id)` on commit. New Celery task `run_engine_job(self, row_id: int)` in `connectors/tasks.py` (`bind=True, acks_late=True, reject_on_worker_lost=True, max_retries=2`).

- [ ] **Step 1: Write failing tests** with a registered fake deferred engine (`provides="analysis"`, offers a `mail_archive` analyzer named by the `ai` role): dispatch of `"mail_archive"` writes one report-less pending row with the namespaced ids, calls `on_started` once, enqueues the task on commit; the task on a `Success` result: row `Success` with `completed_at`, `on_result` called once inside the same transaction, one `ConnectorDelivery(event="analyze", status="success")`, `reconcile_case.delay` queued; on a `Failure` result: row `Failure`, delivery `failed` with the error text, `on_result` called with the failure; a retryable `ProviderUnavailable` is retried twice then the row fails (assert the `retry` countdown formula and the final state); a non-retryable one fails at once without retry; a second delivery of the task for a closed row does nothing (no extra `on_result`, no extra delivery); two concurrent claims close once; the connector disabled after the start still runs; an open breaker fails the row without calling `run`. Review Focus 3.
- [ ] **Step 2: Run** `ww test backend connectors.tests.test_engines_deferred` — expect FAIL.
- [ ] **Step 3: Implement** as in Interfaces. Port the retry/breaker/claim code from `run_provider_analysis` and `finish_provider_analysis` in `connectors/providers.py` and `connectors/tasks.py` (read them; keep behaviour identical, minus anything AI-specific, which Task 3 moves to the connector hooks). Leave the old functions in place until Task 4.
- [ ] **Step 4: Run** the label, then `ww test backend connectors tasp cortex_job` — expect PASS.
- [ ] **Step 5: Commit** `feat(connectors): deferred engine jobs run in a worker`.

### Task 3: `ai_model` on the engine path

**Files:**
- Modify: `Suspicious/Suspicious/connectors/contrib/ai_model/connector.py`, `Suspicious/Suspicious/ai_model/mailinfo.py`, `Suspicious/Suspicious/tasp/tasks.py` (`dispatch_case_analysis`), `Suspicious/Suspicious/mail_feeder/global_submission/gsubmission.py`, `Suspicious/Suspicious/api/views/connectors.py` (guard)
- Test: `Suspicious/Suspicious/connectors/contrib/ai_model/tests/test_engine_path.py` (new, the parity suite), update `connectors/contrib/ai_model/tests/test_connector.py`, `test_shadow_analyze.py`, `ai_model/tests/test_parity.py`, `test_shadow_result.py`, `mail_feeder/global_submission/tests.py`, `tasp/tests/test_dispatch_case_analysis.py`, `api/tests/test_connectors_api.py`

**Interfaces:**
- Consumes: Tasks 1-2.
- Produces: `AiModelConnector`: `provides="analysis"` (import `PROVIDER_KIND_ANALYSIS`), `general_purpose = False`; `catalog(data_type=None, name=None) -> list[CatalogEntry]` returns one entry (`id="mail_classifier"`, the AI role name, `data_types=("mail_archive",)`) only for `name == ai role name` or `data_type == "mail_archive"`, else `[]`; `start(analyzer, data_type, value)` returns `StartResult(job_id=uuid4().hex[:24], deferred=True)`; `run(job_id, data_type, value)` is the body of today's `analyze` returning a `FetchResult` with `state="result"`, `status` `Success` for a normal answer (it has a model version) and `Failure` for no archive, unreadable archive, server refusal and an answer without a model version, `payload` carrying result, score, confidence, category, model_version, assessment, shadow, reason; `on_started(case, name)` marks the AI missing unless the case already has an assessment; `on_result(case, name, result)` is today's `finish_provider_analysis` write on `Success` (case AI fields, `AiAssessment` with every field reset to its default then the result's, `apply_mail_info`, the shadow store in its own savepoint) and on `Failure` the AI-missing rule plus a warning with the reason. In `ai_model/mailinfo.py`: `mark_ai_missing(case)`, `has_assessment(case) -> bool` (moved from `connectors/providers.py`, which re-exports them until Task 4) and `dispatch_mail_ai(case) -> list[str]` which calls `engines.dispatch(value=case, data_type=DATA_TYPE_MAIL_ARCHIVE, case=case)` and calls `mark_ai_missing(case)` when no job started. `dispatch_case_analysis` and `gsubmission` call `dispatch_mail_ai` where they called `queue_mail_ai`. Guard in `ConnectorStateView.patch`: applies only when the connector being disabled is `general_purpose`; counts another enabled analysis connector only if it is not inert and `general_purpose`; the one-per-kind 409 for `provides` is deleted.

- [ ] **Step 1: Write failing tests** `test_engine_path.py` as a port of the current provider tests with the same assertions on case fields, `AiAssessment`, ledger and delivery rows: a normal server answer; INCONCLUSIVE class with a model version (still `Success`); no archive; unreadable archive; server refusal; answer without a model version; server down (retried twice, then AI missing); non-retryable error; shadow answer stored and a shadow failure not touching the live case; an earlier assessment kept when a later job fails (and not marked missing); `on_started` marking at registration, and a row closed by `fail_stale_jobs` leaving `results_ai = Inconclusive` (Review Focus 1 and 2); `dispatch_mail_ai` with no engine offering the role marks the AI missing and returns `[]`; guard tests: Cortex + `ai_model` enabled, disabling Cortex is 409 unless forced, disabling `ai_model` needs no force, `ai_model` alone enabled does not count for disabling Cortex when Cortex is the only general-purpose engine left... (state each combination as a test). Update the existing tests that patch `queue_mail_ai`/`analyze` to the new names, changing only targets and call shapes.
- [ ] **Step 2: Run** `ww test backend connectors.contrib.ai_model ai_model connectors.tests.test_engines_deferred api.tests.test_connectors_api mail_feeder tasp` — expect the new tests FAIL.
- [ ] **Step 3: Implement** as in Interfaces. Read `connectors/providers.py::finish_provider_analysis`, `queue_provider_analysis` and `connectors/contrib/ai_model/connector.py::analyze` and move their behaviour; do not delete the old functions yet (Task 4), but nothing may call them any more.
- [ ] **Step 4: Run** the same labels plus `connectors cortex_job score_process` — expect PASS.
- [ ] **Step 5: Commit** `feat(ai_model): the mail verdict is an analysis-engine job`.

### Task 4: Retire the provider slot, docs, acceptance

**Files:**
- Modify: `Suspicious/Suspicious/connectors/providers.py` (keep only `ProviderUnavailable`), `connectors/base.py` (remove `PROVIDER_KIND_MAIL_AI`, `ProviderResult`, `Connector.analyze`, `VALID_PROVIDER_KINDS` keeps `analysis`), `connectors/registry.py` (`providers()` stays), `connectors/tasks.py` (replace `run_provider_analysis` by a forwarder), `connectors/tests/dummy.py`, delete `connectors/tests/test_providers.py` and `test_provider_dispatch.py` after confirming every case is ported (list them in the report), `docs/components/backend/connectors.md`, `docs/getting-started/ai-inference.md`, `docs/components/analyzers.md` where they name the provider slot, `CHANGELOG.md`, `CLAUDE.md` (flow step 3 and the AI path paragraph)
- Test: `Suspicious/Suspicious/connectors/tests/test_provider_slot_retired.py` (new)

**Interfaces:**
- `connectors.tasks.run_provider_analysis(case_id, kind, job_id)` stays registered (same signature) for one release: it looks up the open `CaseAnalyzerJob` by `job_id`, and if it is pending runs `run_engine_job(job_id)` inline logic (calls the shared function, not `.delay`); a missing or closed row does nothing. A row opened by the old code has a `provider-` id and no report; the engine path treats it like any deferred row.

- [ ] **Step 1: Write failing tests**: `PROVIDER_KIND_MAIL_AI`, `ProviderResult`, `Connector.analyze`, `queue_provider_analysis`, `queue_mail_ai`, `finish_provider_analysis`, `enabled_provider`, `provider_connector` no longer exist (`hasattr` checks); `ProviderUnavailable` still importable from `connectors.providers`; the forwarding task: an open `provider-` row (made by hand, no report) with a fake `ai_model` result gives the same case AI fields and assessment as the engine path; a closed or missing row does nothing; a grep-style test: `connectors/engines.py`, `connectors/tasks.py`, `connectors/base.py` contain none of `ai_model`, `AiAssessment`, `results_ai` (Review Focus 5 and 6).
- [ ] **Step 2: Run** `ww test backend connectors.tests.test_provider_slot_retired` — expect FAIL.
- [ ] **Step 3: Implement** the removals and the forwarder; update the docs (the `mail_ai` provider text becomes "the `ai_model` engine, deferred jobs"; document `on_started`, `on_result`, `run`, `mail_archive`, `general_purpose`; the upgrade note: jobs queued before the upgrade still finish, `ai_model` keeps its name and config, disabling `ai_model` no longer needs `force`); CHANGELOG line.
- [ ] **Step 4: Acceptance, recorded in the ledger:** full `ww test backend` (only the two known `google.api_core` errors tolerated); `backtest_scoring` on this branch diffed against the baseline (identical, 339 cases; baseline from the step 3 branch before Task 1, method in the ledger of step 3); a list of every ported test (old name -> new name).
- [ ] **Step 5: Commit** `refactor(connectors): remove the mail_ai provider slot`.

## Self-Review

- **Spec coverage:** goals 1-5 and every acceptance line of the spec map to Tasks 1-4; the six builder-check decisions map to Task 3 (`on_started`, failures as `Failure`, hooks for deferred jobs only, the guard rules) and Task 2 (disabled-after-start still runs; the engine layer stays AI-free). Not in this plan, by design: wiring `on_result` into `refresh` and the finished-at-start path.
- **Ordering:** Task 3 flips `provides` and the callers in one commit because a connector has a single `provides`; Task 2 leaves the old path untouched so every commit is green.
- **Names:** `DATA_TYPE_MAIL_ARCHIVE`, `StartResult.deferred`, `FetchResult.payload`, `Connector.run`, `on_started`, `on_result`, `general_purpose`, `run_engine_job`, `dispatch_mail_ai`, `mark_ai_missing`, `has_assessment` are spelled identically in every task.
