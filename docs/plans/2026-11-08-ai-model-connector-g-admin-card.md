# AI Model Connector, Plan G: Settings "AI model" Card Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An Admin sees one Settings card, "AI model", that shows the connector's health, the active version, the candidate and its gate result, the shadow comparison with its review and promotion actions, the version history with rollback, the label ledger with flagged labels, and a queue of mails where the AI and the other evidence disagree. The card is hidden when the `ai_model` connector is disabled.

**Architecture:** Most writes and the shadow reads already exist under `/api/ai-model/` (Plan F). Tasks 1 to 5 add the missing backend reads and writes (status extension, candidates with the gate, retrain trigger and job history, ledger summary, flagged labels and resolve, the disagreement queue, breaker state and reset), each a thin view over code that exists. Tasks 6 to 12 add the card in `suspicious-ui` as a new Settings section with one panel per concern, TanStack Query hooks and Vitest tests, then the gallery line, a Playwright path and the docs.

**Tech Stack:** Django and DRF (views over existing services), React 19, TypeScript, MUI v9, TanStack Query v5, Vitest browser mode with Testing Library, Playwright.

**Spec:** `docs/specs/2026-10-30-ai-model-connector-design.md` section 8 (User interface) and section 10 (health). Master plan: `docs/plans/2026-10-30-ai-model-connector.md`, Plan G. Plans A to F are merged in the local `design/ai-model-connector` branch (Plan F at `f936cc3c`). Dev-stack facts from Plan F: `docs/plans/2026-11-08-ai-model-f-acceptance-run.md`.

## Guidance used

Pages named from prior reading and not re-fetched while writing this plan; check them before relying on a detail. Where a page does not answer the question it is said.

- TanStack Query, [invalidations from mutations](https://tanstack.com/query/latest/docs/framework/react/guides/invalidations-from-mutations): a mutation's `onSuccess` invalidates the query keys it changed. The page does not say which keys a screen should group; the grouping here follows the repo's own convention (a root key per feature).
- MUI, [Tabs accessibility](https://mui.com/material-ui/react-tabs/#accessibility) and [Dialog](https://mui.com/material-ui/react-dialog/): tabs need `aria-controls` and `aria-labelledby`, a confirming dialog needs a labelled title. The repo already has `ConfirmDialog.tsx` and `a11y.ts`; the plan reuses them.
- WAI-ARIA Authoring Practices, [alert and status roles](https://www.w3.org/WAI/ARIA/apg/patterns/alert/): live regions announce a result without moving focus. The repo's connector tiles use `role="status"`; the card follows that.
- pybreaker, [project readme](https://github.com/danielfm/pybreaker): a breaker is an in-process object with listeners for state changes. It documents no shared state across processes, so Task 5 publishes the state itself.
- Django, [cache framework](https://docs.djangoproject.com/en/stable/topics/cache/): a cache shared through Redis is visible to every process. The page names no atomicity guarantee for read-modify-write, so Task 5 only stores a state string and an epoch integer.

## Global Constraints

- Backend paths are relative to `Suspicious/Suspicious/`, frontend paths to `suspicious-ui/src/`. Backend tests: `ww test backend <label>`; frontend: `ww test frontend` (the repo's frontend gate also runs `pnpm lint`, see Task 12).
- TDD for every behaviour change; the failing run goes in the report.
- Conventional Commits (subject at most 72, body lines at most 100), no `Co-Authored-By` or `Claude-Session` trailer, explicit `git add <paths>`, nothing pushed, remove a stray root-owned `Suspicious/Suspicious/gunicorn.conf.py` before committing, never stage the root-owned `Suspicious/Suspicious/{log,settings.json,case}`. `.superpowers` is git-ignored.
- Permissions: reads Admin and CISO (`IsAdminOrCISO`), writes Admin only (`IsAdmin`), as Plan F's Ruling F14. A superuser without the Admin group is refused, as there.
- No mail text, subject, address, presigned URL, bucket key or exception text in any new API response, log line, stored error or UI string. Case ids and counts are allowed.
- New list endpoints are paginated with the Plan F `Page` class (default 50, maximum 100); sub-lists in one response use the per-prefix `<prefix>_limit` and `<prefix>_offset` parameters of `ShadowView`.
- Every write endpoint writes a `ModelEvent` through `ai_model/registry.py` (a new action name per write) and answers a refusal with 409 and a fixed message.
- UI: enum-to-text maps live in `features/settings/labels.ts` style modules; no hard-coded colours (theme tokens, `StatusLabel`, `useToneColor`); every control is reachable by keyboard, every result is announced in a `role="status"` region, every destructive action goes through `ConfirmDialog`.
- Docs prose: no em dashes, no filler vocabulary, every claim checked against the code. `CHANGELOG.md` entry for each user-visible change.

## Review Focus

- A user outside the Admin group (CERT, CISO, a plain user, anonymous) sees no "AI model" section, cannot open its URL, and gets 403 from every write endpoint; a CISO may read the API but the Settings page itself stays Admin and CERT only (Task 6).
- With `ai_model` disabled the section is absent from the nav and its URL redirects; enabling it in the gallery makes it appear without a reload (Task 6).
- Retrain, promote, rollback, discard and resolve each need a confirmation, show the server's refusal codes in plain words (409 `codes`), and never leave the card showing a state the server did not confirm (Tasks 7, 9, 10, 11).
- A gate result with a failed check shows which check failed and the numbers, and the Shadow start button stays unavailable for a candidate whose manifest is not eligible (Tasks 2, 8).
- The queue and the flagged-label list never show mail text, subject or sender; a case is identified by its id and a link only (Tasks 4, 11).
- Resetting the breaker does not hide a server that is really down: the next failure re-opens it, and the card shows the state the workers publish, not the web process's own (Task 5).
- Large lists (versions, flags, queue, flips) page without losing the selection or the open dialog (Tasks 9 to 11).

## Calls made in this plan

- **Ruling G1: the card is Admin-only in the UI.** `SettingsPage` admits Admin and CERT today. The "AI model" section is added only when `me.groups` includes `Admin` (spec section 8: "Admin-only"). The read API keeps Admin and CISO from Plan F; a CISO has no Settings page, so nothing changes for them. Cost if wrong: one condition.
- **Ruling G2: visibility follows the connector.** The section is listed when `GET /connectors/enabled/` includes `ai_model` (the same query key `["enabledConnectors"]` the investigation actions use), so the gallery toggle shows or hides it. A direct URL to a hidden section redirects to the first section. Cost if wrong: a stale nav until the next refetch; the toggle already invalidates that key.
- **Ruling G3: one status endpoint grows, no second one.** `GET /api/ai-model/status/` gains `health` (the connector's stored `last_health_*`), `breaker` (`{state, since}` from Task 5), `schedule` (`{enabled, interval_days, next_run, backoff_until}`), `counts` (versions by status), `jobs` (the last five `RetrainJob` rows without error text beyond the stored 200 characters) and `ledger` (`ledger_summary()`). One request fills the card's header; the heavy lists keep their own endpoints. Cost if wrong: a wider payload, still bounded.
- **Ruling G4: next retrain is computed, not stored.** There is no stored schedule value. `next_run` = newest version `created_at` plus `retrain_interval_days` (default 30) when `retrain_enabled` is true, pushed to the end of the 7-day backoff after a failed or refused scheduled job (`retrain.BACKOFF`); it is `null` when scheduling is off or a job runs. The card says "about", because the beat check runs once a day. Cost if wrong: the date may be off by a day.
- **Ruling G5: the gate is whitelisted, not the manifest.** `GET /api/ai-model/candidates/` returns, per candidate, `{version_id, created_at, trigger, rows, excluded_rows, eligible, gate: {checks, candidate, baseline, campaign, tier_cutoffs}}` built from `ModelVersion.manifest` with the `GATE_KEYS` whitelist and a depth-limited copy (numbers, booleans and short strings only; details strings capped at 300 characters). The manifest, bundle prefix and URLs stay hidden. Cost if wrong: a new gate key needs a line in the whitelist.
- **Ruling G6: retrain is a POST with the same refusals as the command.** `POST /api/ai-model/retrain/` calls `retrain.start_retrain(user, trigger=MANUAL)` and answers 202 `{job_id}`; `RetrainRefused` (and `JobRunning`) become 409 through the existing `WriteMixin`. `GET /api/ai-model/jobs/` pages the `RetrainJob` history. A job's progress is read from the existing `status/` `job_running`; the card polls it every 10 s only while a job runs.
- **Ruling G7: flagged labels and resolve.** `GET /api/ai-model/flags/` pages `LabelRecord.objects.filter(status="flagged")` as `{id, case_id, label_class, source, flag_reason, observed_at}` (no message id text, no subject, no sender). `POST /api/ai-model/flags/<id>/resolve/` takes `{keep: bool, note}` and calls `ledger.resolve_flag(record, user, note, keep=keep)`; a `ValueError` (already closed) becomes 409. `GET /api/ai-model/ledger/` returns `ledger_summary()` plus the label mix for the jump warning (Ruling G8). Cost if wrong: none beyond a field name.
- **Ruling G8: the jump warning.** The ledger summary compares the Dangerous, Safe and Unwanted shares of the active folder rows now with the share 30 days ago (rows created before that date); a change of more than 15 percentage points in one class, with at least 50 rows in each window, sets `jump: {class, from, to}`. The constants live in `ai_model/ledger.py`. Cost if wrong: a threshold edit.
- **Ruling G9: the queue is two bounded lists.** `GET /api/ai-model/queue/` returns `disagreements` (finalised mail cases of the last 30 days whose latest `AiAssessment` class is on the opposite side of the Safe/Dangerous axis from the case verdict and where the AI did not decide the band, the rule of `presentation.cross_check`) and `campaign_conflicts` (live campaigns whose labelled members include both Dangerous and Safe, `presentation._members_disagree`), each `{count, results}` with `case_id` or `campaign_ref`, the two classes, and the date. Each list is capped at 200 rows before paging. Cost if wrong: a very old disagreement does not show; the window is a constant.
- **Ruling G10: breaker state is published by the workers.** `pybreaker` state is per process, so `common/http_client.py` gains a `CircuitBreakerListener` that writes `{state, since}` to the shared Django cache key `breaker:<name>` on every state change, and the card reads that. Reset is `POST /api/ai-model/breaker/reset/`: it writes an increasing epoch to `breaker-epoch:<name>`; `get_breaker` callers compare the epoch before a call and `close()` their own breaker when it moved. A reset of a server that is really down re-opens after five failures, as today. Cost if wrong: if the shared cache is down the card shows "unknown" and the reset answers 503; the breaker itself keeps working as before. This is the riskiest backend task and is separable: if it is dropped, the card shows the state only.
- **Ruling G11: no new frontend dependency.** Tables are MUI `Table`, tabs are MUI `Tabs`, confirmations are `ConfirmDialog`, toasts are the existing `useSnackbar`. No chart library: agreement and counters are tables with a proportion bar built from a `Box`. Cost if wrong: less polish.
- **Ruling G12: one polling rule.** Queries refetch on window focus and on the section's own Refresh; only the status query polls (30 s, like `useFeederHealth`), and the jobs query polls every 10 s while a job runs. Cost if wrong: up to 30 s of staleness.

## Contracts

- Status (extends Plan F): `GET /api/ai-model/status/` adds `health: {ok: bool|null, detail: str, checked_at: str|null}`, `breaker: {state: "closed"|"open"|"half-open"|"unknown", since: str|null}`, `schedule: {enabled: bool, interval_days: int, next_run: str|null, backoff_until: str|null}`, `counts: {candidate: int, shadow: int, active: int, previous: int, discarded: int, failed: int}`, `jobs: [{job_id, state, trigger, rows, excluded_rows, started_at, finished_at, error}]`, `ledger: {by_source, flagged, trainable}`; the existing keys stay.
- New endpoints under `/api/ai-model/`: `GET candidates/`, `POST retrain/`, `GET jobs/`, `GET ledger/`, `GET flags/`, `POST flags/<int:pk>/resolve/`, `GET queue/`, `POST breaker/reset/`. Reads `IsAdminOrCISO`, writes `IsAdmin`.
- `ai_model/ledger.py`: `label_mix(now=None) -> dict` returning `{"now": {class: share}, "before": {class: share}, "rows": {"now": int, "before": int}, "jump": {...}|None}`.
- `ai_model/schedule.py` (new): `next_run(now=None) -> datetime | None`, `backoff_until(now=None) -> datetime | None`.
- `ai_model/queue.py` (new): `disagreements(since_days=30, cap=200) -> list[dict]`, `campaign_conflicts(cap=200) -> list[dict]`.
- `common/http_client.py`: `breaker_state(name) -> dict`, `request_reset(name) -> int` (the new epoch); the listener and epoch check are internal.
- Frontend: `features/aiModel/api.ts` (fetchers and types), `features/aiModel/queryKeys.ts` (root key `"ai-model"`), `features/aiModel/hooks.ts` (one hook per query and per mutation), `features/aiModel/components/*Panel.tsx`, `features/aiModel/labels.ts`; the section key is `"ai_model"` in `features/settings/components/sections.tsx`.

---

### Task 1: Status extension

**Files:** Modify `api/views/ai_model.py` (`StatusView`), `api/serializers/ai_model.py`. Create `ai_model/schedule.py`. Modify `ai_model/ledger.py` (`label_mix`, used by Task 4 too). Tests `ai_model/tests/test_schedule.py`, `api/tests/test_ai_model_api.py` (extend).

- [ ] **1. Tests first (schedule):** `next_run` is the newest version `created_at` plus `retrain_interval_days`; `None` when `retrain_enabled` is false or a job runs; after a failed or refused scheduled job it is pushed to the end of the 7-day backoff; `backoff_until` is `None` without a recent scheduled failure.
- [ ] **2. Tests first (API):** `status/` returns the new keys with the Contracts shapes; `health` mirrors the connector's stored `last_health_*`; `counts` has all six statuses (zeros included); `jobs` returns at most five rows, newest first, with `error` capped at 200 characters; `ledger` equals `ledger_summary()`; no key carries a URL, a manifest or mail text; CISO reads, CERT gets 403.
- [ ] **3. Implement** `schedule.next_run` and `backoff_until` from the connector config (`retrain_enabled`, `retrain_interval_days`) and `retrain.BACKOFF`; extend `StatusView` without a second query per field (one `values("status").annotate`, one slice for jobs). `breaker` answers `{"state": "unknown", "since": null}` until Task 5.
- [ ] **4. Run** `ww test backend ai_model api`. Commit: `feat(api): add health, schedule, counts and jobs to the AI model status`.

### Task 2: Candidates and the gate

**Files:** Modify `api/views/ai_model.py`, `api/serializers/ai_model.py`, `api/urls.py`. Tests `api/tests/test_ai_model_api.py`.

- [ ] **1. Tests first:** `candidates/` lists versions in status `candidate` and the current shadow (newest first, paged) with `eligible` and the whitelisted `gate`; a manifest key outside the whitelist, `bundle_prefix` and any `http` string never appear (assert on the serialised JSON text); nested values are numbers, booleans and strings of at most 300 characters; a candidate without a gate (version 0) has `gate: null`; the failed check names are present (`calibration_error`, `high_tier_precision` in the Plan F dev run); reads Admin and CISO, nobody else.
- [ ] **2. Implement** a `gate_view(manifest) -> dict | None` helper in the serializers module with the `retrain.GATE_KEYS` whitelist and the caps; the view is a paged list.
- [ ] **3. Run** `ww test backend api`. Commit: `feat(api): list AI model candidates with their gate result`.

### Task 3: Retrain trigger and job history

**Files:** Modify `api/views/ai_model.py`, `api/serializers/ai_model.py`, `api/urls.py`, `ai_model/registry.py` only if an event helper is missing. Tests `api/tests/test_ai_model_api.py`.

- [ ] **1. Tests first:** `POST retrain/` answers 202 `{job_id}` and writes a `ModelEvent` (`retrain_requested`, user, note); while a job runs it answers 409 with the fixed message and no second job; a `RetrainRefused` (no trainable rows, patched) answers 409 with the refusal's fixed text and no exception text; `jobs/` pages `RetrainJob` newest first with the Contracts fields; Admin only for the POST; CISO may read `jobs/`.
- [ ] **2. Implement** both views over `retrain.start_retrain(user, trigger=MANUAL)` and the `WriteMixin`.
- [ ] **3. Run** `ww test backend api ai_model`. Commit: `feat(api): start a retrain and list retrain jobs`.

### Task 4: Ledger, flags and the queue

**Files:** Modify `ai_model/ledger.py` (`label_mix`, `list_flagged`), create `ai_model/queue.py`, modify `api/views/ai_model.py`, `api/serializers/ai_model.py`, `api/urls.py`. Tests `ai_model/tests/test_label_mix.py`, `ai_model/tests/test_queue.py`, `api/tests/test_ai_model_api.py`.

- [ ] **1. Tests first (mix):** shares per class now and 30 days ago; `jump` set only with at least 50 rows in each window and a change above 15 points, and names the class; empty ledger gives empty shares and `jump: null`.
- [ ] **2. Tests first (flags):** `flags/` lists flagged rows without message id, subject or sender; `resolve/` with `keep=true` and `keep=false` calls `resolve_flag`, writes a `ModelEvent` (`flag_resolved`, user, note with the id and the choice), and a second resolve answers 409; a missing note answers 400; writes Admin only.
- [ ] **3. Tests first (queue):** `disagreements` contains a Safe-verdict case with a Dangerous AI class and not a case where the AI decided the band (rule `ai-classifier-decisive`), not a case older than the window, not a non-mail case; `campaign_conflicts` lists a campaign with labelled Dangerous and Safe members and not one with agreeing labels; each list is capped at 200 before paging and carries ids and classes only.
- [ ] **4. Implement** per Rulings G7 to G9, reusing `presentation._members_disagree` and the cross-check rule through small public wrappers (rename the private helpers only if an import would otherwise reach into them).
- [ ] **5. Run** `ww test backend api ai_model`. Commit: `feat(api): add the label ledger, flagged labels and the review queue`.

### Task 5: Breaker state and reset

**Files:** Modify `common/http_client.py`, `api/views/ai_model.py`, `api/urls.py`. Tests `common/tests/test_breaker_state.py`, `api/tests/test_ai_model_api.py`.

- [ ] **1. Tests first:** a listener writes `{state, since}` to the cache key `breaker:<name>` on each state change; `breaker_state` returns it, or `unknown` when the key is missing or the cache raises; `request_reset` increments `breaker-epoch:<name>`; a breaker whose recorded epoch is older than the cached one is closed before the next call and records the new epoch; a reset does not stop five new failures from opening it again; `POST breaker/reset/` is Admin only, writes a `ModelEvent`-style audit line to the connector's delivery ledger or the registry log (use `registry.record_breaker_reset`, a new action `breaker_reset` on version 0's events when no other version exists), and answers 503 with a fixed message when the cache is down.
- [ ] **2. Implement** per Ruling G10; fill `status/` `breaker` from `breaker_state("ai_model")`.
- [ ] **3. Run** `ww test backend common api ai_model connectors`. Commit: `feat(ai-model): publish the circuit breaker state and add a reset`. If this task proves unsafe in review, drop it and keep `breaker: unknown` with a card line "state not available".

### Task 6: Section, visibility and data layer

**Files:** Create `features/aiModel/{api.ts,queryKeys.ts,hooks.ts,labels.ts}`, `features/aiModel/components/AiModelPanel.tsx` (empty shell with a heading). Modify `features/settings/components/sections.tsx`, `pages/SettingsPage.tsx` (`REFRESH_ROOTS` gets `"ai-model"`), `features/settings/components/SettingsNav.tsx` if it filters sections. Tests `features/aiModel/__tests__/hooks.test.tsx`, `features/settings/components/__tests__/sections.test.tsx`, `SettingsNav.test.tsx`, `pages/__tests__/SettingsPage.test.tsx` and the a11y test (mock the new module).

- [ ] **1. Tests first:** the section key `ai_model` is in `SECTIONS` (group `integrations`) and appears in the nav only for a user in the `Admin` group while `getEnabledConnectors` includes `ai_model`; for a CERT-only user, a user without the group and with the connector disabled, it is absent and `/settings/ai_model` redirects to the first section; enabling the connector in the gallery makes it appear without a reload (invalidates `["enabledConnectors"]`, which `ConnectorTile` already does); the existing section tests that enumerate `SECTIONS` stay green.
- [ ] **2. Tests first (hooks):** `useAiModelStatus` polls every 30 s and uses `["ai-model", "status"]`; a mutation hook invalidates `["ai-model"]` on success and shows the snackbar message from `labels.ts` on a 409 with `codes`; the code-to-text map covers every code Plan F returns (`not_shadow`, `too_young`, `too_few_results`, `unreviewed_flips`, `unreviewed_campaigns`, `recheck_missing`, `recheck_failed`, `recheck_stale`, `profile_window`, `job_running`, `no_previous`, `state_changed`).
- [ ] **3. Implement** the fetchers for every endpoint in Contracts (plain `async` functions like `features/settings/components/connectors.ts`), the query keys, the hooks, and the visibility rule in `SectionContent`/`SECTIONS` consumers; the panel is a tabbed shell (Overview, Candidate, Shadow, Versions, Ledger) whose tabs are filled by Tasks 7 to 11.
- [ ] **4. Run** `ww test frontend` for the touched files and `node_modules/.bin/eslint` on the new folder. Commit: `feat(ui): add the AI model section, its data layer and visibility rule`.

### Task 7: Overview tab (health, version, schedule, retrain)

**Files:** Create `features/aiModel/components/OverviewTab.tsx`, `RetrainButton.tsx`. Tests `features/aiModel/components/__tests__/OverviewTab.test.tsx`.

- [ ] **1. Tests first:** health shows ok, failing (with the stored detail) or never checked; breaker shows its state in words with a reset button only when the state is `open` or `half-open`, behind a `ConfirmDialog`, announcing the result in a `role="status"` region; the active version shows its id, its age in days and the "Confidence not calibrated" note for version 0; a version older than 60 days shows the age warning; the label counts by class and source render from `ledger.by_source`; the schedule shows "Automatic retrain every N days, next about <date>" or "Off", and "waiting until <date> after a failed run" during a backoff; the Retrain button asks for confirmation, calls the POST, disables itself while `job_running`, shows the job state and rows while a job runs, and shows the refusal text of a 409; a succeeded job offers "See candidate" (switches to the Candidate tab).
- [ ] **2. Implement** the tab from `useAiModelStatus` and `useRetrain`; polling of jobs every 10 s only while `job_running`.
- [ ] **3. Run** `ww test frontend` for the folder. Commit: `feat(ui): AI model overview with health, schedule and retrain`.

### Task 8: Candidate and gate tab

**Files:** Create `features/aiModel/components/CandidateTab.tsx`, `GateTable.tsx`. Tests `__tests__/CandidateTab.test.tsx`.

- [ ] **1. Tests first:** the newest candidate shows rows, excluded rows, trigger and date; the gate table lists every check with passed or failed, the value and the threshold, failed checks first and marked in words (not by colour alone); the campaign held-out result shows its own line (Dangerous called Safe against baseline, groups); the tier cutoffs show as High and Medium numbers; "Start shadow" is enabled only when `eligible` and no shadow exists, asks for confirmation, calls the POST, and shows a 409 text; an ineligible candidate names the failed checks beside the disabled button; "Discard" asks for confirmation; with no candidate the empty state says so; no manifest value outside the whitelist can render.
- [ ] **2. Implement** per Ruling G5 using the `candidates/` data and the existing `shadow/start/` and `discard/` mutations.
- [ ] **3. Run** `ww test frontend` for the folder. Commit: `feat(ui): AI model candidate tab with the gate table`.

### Task 9: Shadow tab

**Files:** Create `features/aiModel/components/ShadowTab.tsx`, `AgreementTable.tsx`, `FlipsList.tsx`, `CampaignEffects.tsx`, `PromotionConditions.tsx`, `ReviewDialog.tsx`. Tests `__tests__/ShadowTab.test.tsx`.

- [ ] **1. Tests first:** with no shadow the tab says so and points to the Candidate tab; with a shadow it shows the age against `shadow_min_days`, the live result count against 500 (a bar plus text), and the agreement tables (class and verdict) from `agreement`; the flips list shows only critical ones as reviewable (`reviewable: true`), each with a Review button that opens a dialog requiring a note of at most 2000 characters, posts `reviews/` with `case_id` as an integer, and then shows "reviewed"; non-critical changes are listed without a button; the campaign effects table and the alert delta (candidate only, active only) page with their own `_limit/_offset` and show case ids only; `PromotionConditions` lists each unmet code in words and the met ones as done, and "Promote" is enabled only when `conditions` is empty, asks for confirmation naming the version, and on a 409 re-fetches and shows the codes; "Extend" takes a new total of days above the current one; "Recheck" starts a job and shows its result when `recheck` changes; "Discard" confirms; a mutation in flight disables the other three actions; lists keep their page after a review.
- [ ] **2. Implement** with the Plan F `shadow/` response and the existing mutations.
- [ ] **3. Run** `ww test frontend` for the folder. Commit: `feat(ui): AI model shadow tab with reviews, conditions and promotion`.

### Task 10: Versions tab

**Files:** Create `features/aiModel/components/VersionsTab.tsx`. Tests `__tests__/VersionsTab.test.tsx`.

- [ ] **1. Tests first:** the table lists versions newest first with status, created date, trigger and, per version, scored and Dangerous counts, campaigns created and joined, alerts, purity with its labelled count and the warnings (low purity with at least 10 labelled members, age over 60 days) in words; version 0 reads "v0 (the original model)"; the `previous` row has a Rollback button that confirms, names both versions, calls the POST and shows the 409 text (`no_previous`, `state_changed`); there is no rollback on other rows; paging keeps the open dialog; an empty history shows the empty state.
- [ ] **2. Implement** from `versions/` and the rollback mutation.
- [ ] **3. Run** `ww test frontend` for the folder. Commit: `feat(ui): AI model version history with counters and rollback`.

### Task 11: Ledger and queue tab

**Files:** Create `features/aiModel/components/LedgerTab.tsx`, `FlagsList.tsx`, `QueueLists.tsx`. Tests `__tests__/LedgerTab.test.tsx`.

- [ ] **1. Tests first:** the label mix shows counts by class and source and the share now against 30 days ago, with the jump warning naming the class and both shares; flagged labels list case id, class, source, reason in words (`folder_verdict_mismatch` becomes "folder label disagrees with the analyst verdict") and date, each with "Keep label" and "Drop label" buttons that confirm, require a note, post `resolve/` with `keep`, and remove the row on success; a 409 says it was already closed and refreshes; the queue shows the two lists (AI disagrees with the evidence; campaign members disagree) with a link per case id to the investigation page (`/investigations/<id>` as the router defines it, check `app/router.tsx`) and nothing else about the mail; both lists page; empty states.
- [ ] **2. Implement** from `ledger/`, `flags/`, `queue/` and the resolve mutation.
- [ ] **3. Run** `ww test frontend` for the folder. Commit: `feat(ui): AI model ledger, flagged labels and review queue`.

### Task 12: Gallery line, end-to-end path, docs, gate

**Files:** Modify `features/settings/components/ConnectorTile.tsx` (or `ConnectorOverview.tsx`), create `suspicious-ui/e2e/ai-model.spec.ts`, modify `docs/components/analyzers.md`, `CHANGELOG.md`, `docs/plans/2026-10-30-ai-model-connector.md` (Plan G status), `docs/specs/2026-10-30-ai-model-connector-design.md` section 8 (the amendments: Settings is Admin and CERT, the card Admin only; breaker state published through the cache; queue windows). Tests `ConnectorTile.test.tsx`.

- [ ] **1. Tests first (gallery):** the `ai_model` tile shows a read-only line "Models, retraining and shadow are managed in the AI model card" with a link to `/settings/ai_model` only for an Admin; other tiles and other users are unchanged.
- [ ] **2. Playwright path** `ai-model.spec.ts` with `page.route` mocks like `e2e/ai-assessment.spec.ts` (an Admin `me`): open the card, start a retrain (202, then a succeeded job), see the candidate and its failed gate check, start a shadow for an eligible mock, review a flip, see the unmet conditions drop, promote, see the version list and roll back; a 409 with codes is shown in words; a CERT-only `me` has no section.
- [ ] **3. Docs and changelog:** the card, the new endpoints (paths, parameters, codes), the breaker publication, the schedule rule, the queue windows; every statement checked against the code.
- [ ] **4. Delivery gate:** frontend `node_modules/.bin/eslint . -f json` (the host has no `pnpm`; read errors and warnings, compare warnings with the four known ones), `ww test frontend` full run, the repo's accessibility tests for Settings, dash, filler, invisible-character, trailer and commit-length scans over the branch diff, the full backend suite.
- [ ] **5. Dev-stack look:** rebuild `suspicious` and `suspicious_ui` per `dev-stack-redeploy`, open the card against the dev data from the Plan F acceptance run (one candidate that failed its gate), record a screenshot path in the report. Operator step if the browser is not available to the executor.
- [ ] **6. Run** the commands of step 4. Commit: `docs(ai-model): document the AI model card and its endpoints`.

---

## Self-review

- **Spec coverage (section 8, card):** server health and breaker with reset (T1, T5, T7); active version, age, label counts by class and source (T1, T7); schedule and Retrain (T1, T3, T7); latest candidate and gate including campaign held-out (T2, T8); shadow comparison, review list, campaign dry-run table and alert delta (T9, existing Plan F endpoints); version history with rollback, campaign counters and purity (T10); label ledger summary and flagged list with resolve (T4, T11); the queue (T4, T11); connector gallery line (T12). Hidden when disabled and admin-only (T6). API list of the spec (status, versions, candidate, shadow comparison, ledger summary; writes retrain, promote, discard, rollback, extend, review, resolve) is complete with T1 to T5 plus Plan F.
- **Not in this plan:** a chart library, a live per-case AI panel (Plan C), notifications when a gate fails, editing the connector's configuration from the card (the existing drawer keeps that), automatic promotion (spec, out), the System 1 backlog.
- **Types:** `status` keys, `candidates` shape, `queue` lists and the query-key root `"ai-model"` are defined once in Contracts and Calls and used with the same names in tasks 1 to 12.
- **Open risks:** Task 5 is the one backend task with cross-process behaviour; it is separable. The Settings page tests enumerate sections and need updating in Task 6. Frontend components are written against Plan F's response shapes, which are covered by `api/tests/test_ai_model_api.py`.
