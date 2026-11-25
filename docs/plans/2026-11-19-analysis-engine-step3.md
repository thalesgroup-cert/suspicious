# Fixture analysis engine, step 3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An in-tree analysis connector that answers instantly from fixed rules, off by default and inert until explicitly confirmed, so CI and a dev stack can run the whole pipeline with no Cortex; plus the deferred finished-start fix that an instant engine needs.

**Architecture:** `connectors/contrib/fixture/` implements `catalog`, `start` (returns an already finished result) and `fetch`. Before it ships, the finished-result path in `engines._start` is made to share one "store a fetched result" function with `engines.refresh`, so an instant engine obeys the same body and data-type rules as a polled one.

**Tech Stack:** Django 5 / DRF, the connector framework from steps 1 and 2.

**Spec:** `docs/specs/2026-11-16-analysis-engine-connectors-design.md` ("Steps", step 3). Builds on branch `feat/analysis-engine-layer`.

## Global Constraints

- `backtest_scoring` output identical before and after (baseline recorded on the base commit first).
- No migration. Nothing under `score_process/`. No change to reconcile's state machine, `finalise`, derived observables or the `case_finalised` event.
- Connector name `fixture_engine`; `provides="analysis"`; `category="Analysis"`; `enabled_by_default=False`.
- The engine is **inert until confirmed**: config field `confirm_fixture` (bool, default `False`); while it is not `True`, `catalog()` returns `[]` and `health_check()` returns `ok=False` with detail `"fixture engine is inert: set confirm_fixture to true (never in production)"`. Reason: an enabled fixture engine scores everything it cannot recognise as safe.
- Analyzer names all start with `Fixture_` so every stored report is visibly fake.
- Verdict rule, by case-insensitive substring of the analysed value (for a file, its path): contains `malicious`, `phish` or `evil` → level `malicious`; contains `suspicious` → `suspicious`; anything else → `safe`.
- Offered analyzers: by data type `url`, `domain`, `ip`, `hash`, `mail` → `Fixture_Reputation_1_0`; by name only (role analyzers, so the existing role configuration points at them) → `Fixture_Yara_1_0` (data types `file`, `mail_body`), `Fixture_FileInfo_1_0` (`file`), `Fixture_Sandbox_1_0` (`file`), `Fixture_Header_1_0` (`mail_header`).
- The result it returns is `FetchResult("result", "Success", summary={"taxonomies": [{"level": <level>, "namespace": "Fixture", "predicate": "Verdict", "value": <level>}]}, full={"results": [{"threat": <level>, "value": <analysed value>}]}, data_type=<the data type it was started with>)`. The default taxonomy parser scores it; no parser is added.
- `start` returns `StartResult(job_id=f"fixture-{uuid4().hex[:24]}", finished=<that result>)`. `fetch` returns `FetchResult("gone")` (an instant engine keeps nothing). `webhook` is not implemented (the generic route answers 404).
- Commits: Conventional Commits, subject at most 72 characters, explicit `git add <paths>`, no `Co-Authored-By`. Tests via `ww test backend <label>` from the worktree.

## Review Focus

1. **Safety of the fixture engine:** enabled by mistake or without `confirm_fixture` it must offer nothing and never produce a "safe" report for a real case (Task 2).
2. **Instant results obey the polled rules:** a finished result with no body leaves the report's status as it was and still scores on Success; a data-type mismatch writes nothing and leaves the row pending (Task 1).
3. **Verdict rule edge cases:** a value containing two markers takes the more severe level; a file path whose directory (not its name) contains `evil`; an empty or `None` value (dispatch already skips it, the engine must not crash).
4. **Coexistence with Cortex:** both enabled gives rows from both for the same URL; the same `Analyzer.name` is never offered by both (names are `Fixture_` prefixed) (Task 2).
5. **Cortex disabled, fixture enabled:** a mail case (body, header, attachment, URL) finalises with every role analyzer answered by the fixture engine and no call to Cortex (Task 2).

---

### Task 1: One function stores a fetched result

**Files:**
- Modify: `Suspicious/Suspicious/connectors/engines.py` (`refresh`, `_start`, `apply_result`)
- Test: `Suspicious/Suspicious/connectors/tests/test_engines_refresh.py`, `connectors/tests/test_engines_dispatch.py`

**Interfaces:**
- Produces in `connectors.engines`: `store_result(report: AnalyzerReport, result: FetchResult) -> bool`: the body-and-data-type rules `refresh` applies today, extracted unchanged: returns `False` and writes nothing when `result.data_type` is non-empty and does not match `report.type` (with `mail_body` matching `file`); otherwise applies `apply_result`, saves the changed fields, and returns `True`. A `Failure` with no body is still written (status only); a `Success` with no body leaves the status as it was. `refresh` and the finished-start path in `_start` both call it; scoring on `Success` stays where it is in each caller.
- Consumes: Step 2's `apply_result`, `_score`, `FetchResult.data_type`.

- [ ] **Step 1: Write failing tests** (in `test_engines_dispatch.py`, class `FinishedStartRulesTest`, with a fake instant engine): a finished result with a body stores summary, taxonomy and full and closes the row with `completed_at`; a finished `Success` with no body leaves the report `InProgress`, the row pending, and still scores; a finished result whose `data_type` mismatches writes nothing (report still `ongoing`, row pending) and logs a warning; a `mail_body` start whose finished result says `file` is accepted; a finished `Failure` with no body closes the row as `Failure`. In `test_engines_refresh.py`: the existing refresh tests still pass unchanged.
- [ ] **Step 2: Run** `ww test backend connectors.tests.test_engines_dispatch connectors.tests.test_engines_refresh` — expect the new tests FAIL.
- [ ] **Step 3: Implement** `store_result` as described and route both callers through it. No behaviour change for `refresh`.
- [ ] **Step 4: Run** the same labels plus `connectors cortex_job` — expect PASS.
- [ ] **Step 5: Commit** `refactor(connectors): one rule set for stored engine results`.

### Task 2: The fixture engine

**Files:**
- Create: `Suspicious/Suspicious/connectors/contrib/fixture/__init__.py`, `.../fixture/connector.py`
- Modify: `Suspicious/Suspicious/connectors/contrib/__init__.py` (`BUILTIN_CONNECTOR_PATHS`)
- Test: `Suspicious/Suspicious/connectors/tests/test_contrib_fixture.py` (new), `connectors/tests/test_fixture_pipeline.py` (new)

**Interfaces:**
- Consumes: Task 1's `store_result` (through `engines.dispatch`), the contract types from step 2.
- Produces: `class FixtureEngineConnector(Connector)` in `connectors.contrib.fixture.connector`, registered name `fixture_engine`, behaving as in Global Constraints.

- [ ] **Step 1: Write failing tests** `test_contrib_fixture.py`: manifest values (name, provides, category, `enabled_by_default is False`, the single `confirm_fixture` bool field defaulting to `False`); inert state (`catalog()`, `catalog(data_type="url")`, `catalog(name="Fixture_Yara_1_0")` all `[]` and `health_check().ok is False` with the detail text) when `confirm_fixture` is missing or not exactly `True` (try `"true"`, `1`); confirmed state: by-type catalog for each of `url`, `domain`, `ip`, `hash`, `mail` returns only `Fixture_Reputation_1_0`; by-name catalog returns the four role analyzers with their data types; `start` verdicts for `http://good.example/`, `http://evil.example/`, `Phish.example`, a value with both `suspicious` and `evil` (→ `malicious`), a path `/tmp/evil/report.pdf` (→ `malicious`), and an empty string / `None` (→ `None`, no crash); the finished result has exactly the shape in Global Constraints and `data_type` echoes the one passed; `fetch` returns `FetchResult("gone")`; `webhook` raises `NotImplementedError`. `test_fixture_pipeline.py` (real `dispatch` and `reconcile_case_core`, no patching of the engine layer): Cortex disabled, fixture enabled and confirmed, roles configured to the four `Fixture_*` names: a URL case and a mail case (body, header, one file) each get rows only from the fixture engine, all closed at dispatch, and finalise; the mail verdict follows the markers; fixture enabled but not confirmed: no rows, the case finalises "no analyzer applicable" and a warning is logged; both Cortex (patched connector operations) and fixture enabled: one URL case holds rows from both and waits for the Cortex row.
- [ ] **Step 2: Run** `ww test backend connectors.tests.test_contrib_fixture connectors.tests.test_fixture_pipeline` — expect FAIL.
- [ ] **Step 3: Implement** `FixtureEngineConnector` and register it; the verdict rule, offered analyzers and result shape exactly as in Global Constraints. No network, no database access inside the connector.
- [ ] **Step 4: Run** the labels, then `ww test backend connectors tasp api.tests.test_connectors_api` (tests that enumerate registered connectors may need their expected lists updated; change only the expectation).
- [ ] **Step 5: Commit** `feat(connectors): fixture analysis engine for tests and dev stacks`.

### Task 3: Docs and the Cortex-less dev recipe

**Files:**
- Modify: `docs/components/backend/connectors.md`, `CHANGELOG.md`, `CLAUDE.md` (a short note in the Full E2E section), `docs/getting-started/examples/Suspicious-settings.example.json` only if a comment-free addition is possible (otherwise leave it and document in prose)
- Test: none (docs); the acceptance step below runs the whole suite.

- [ ] **Step 1: Write the docs.** `connectors.md`: a "Fixture engine" subsection: purpose, the inert-until-`confirm_fixture` rule and why, the verdict markers, the offered analyzer names, never enable it in production. A "Running without Cortex (dev)" recipe: enable `fixture_engine` and set `confirm_fixture`, disable `cortex`, set `integrations.cortex.analyzers` to `yara=Fixture_Yara_1_0`, `file_info=Fixture_FileInfo_1_0`, `sandbox=Fixture_Sandbox_1_0`, `header=Fixture_Header_1_0`; what to expect (every report named `Fixture_*`, verdicts by marker). `CHANGELOG.md`: one line. `CLAUDE.md`: two sentences under the E2E section pointing at the recipe.
- [ ] **Step 2: Acceptance, recorded in the ledger:** full `ww test backend` (tolerate only the two known `google.api_core` errors); the backtest on this branch diffed against the baseline (identical, 339 cases).
- [ ] **Step 3: Commit** `docs(connectors): fixture engine and running without Cortex`.

## Self-Review

- **Spec coverage:** step 3 of the spec ("an in-tree analysis connector, off by default, that answers instantly from fixed data; proves several engines per case and runs with Cortex disabled; gives CI and the dev stack a pipeline with no Cortex container") is Tasks 2 and 3; the deferred finished-start inconsistency from step 2's review (Minor 8) is Task 1. The inert-until-confirmed rule is an addition for safety, not in the spec text.
- **Out of scope, still deferred:** breaker around `catalog` and `start` (no network in the fixture engine; Cortex's own `fetch` owns its breaker), the mail AI verdict on the contract (step 4), the `CortexJob` / `CortexJobManager` forwarders.
- **Names:** `store_result`, `FixtureEngineConnector`, `fixture_engine`, `confirm_fixture`, and the five `Fixture_*` analyzer names are spelled identically in every task.
