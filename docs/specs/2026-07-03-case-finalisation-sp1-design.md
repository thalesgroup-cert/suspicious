# SP1 — Case Lifecycle State Machine + Unified Reconciliation

**Status:** Design approved, pending spec review
**Date:** 2026-07-03
**Author:** Théo (with Claude)
**Part of:** Case-finalisation modernization program (SP1 → SP2 → SP3)

## Context

The current case-finalisation path (`finalise_case` → `get_results` →
`generate_description` → `get_report`) has three structural problems:

1. **Three divergent finalise triggers**, each keyed on a `CaseAnalyzerJob`
   existing: the Cortex webhook (`process_cortex_job`), the
   `update_ongoing_cases` cron, and dispatch-time. A case that dispatches
   **zero** analyzers (no enabled analyzer matches its observable type) creates
   zero ledger rows, so **no trigger ever fires** and the case hangs in
   `On Going` forever — displaying the fail-dangerous default verdict
   `Suspicious`. (Confirmed live: URL/IP submissions with no matching analyzer.)
2. **Implicit, unguarded state.** `case.status` is a bare string set from six
   scattered call sites with no legal-transition enforcement; `To Do` is
   vestigial (cases are born `On Going`).
3. **The completion decision is wrong and fused.** `generate_description`'s
   predicate `all_done = bool(total_reports) and …` treats "zero analyzers" as
   "not finished," and the method fuses the terminal decision with description
   text and persistence.

An interim hotfix (three edits: pending-based completion in
`generate_description`, `Failure` verdict for zero-report cases in
`update_case_results`, dispatch-time finalise-on-zero in `dispatch_pending`)
is live on the branch and proven (cases 10/11 finalise to `Done/Failure`). **SP1
supersedes and absorbs that hotfix.**

## Scope

**In:** the case lifecycle state model, the three finalise triggers, and the
reconciliation orchestration that runs after analyzer reports land.

**Out (deferred):**
- SP2 — typed aggregation replacing the string-ID-set buckets, splitting
  `generate_description`, side-effect idempotency incl. the KPI double-count bug,
  a sane `Result` default.
- SP3 — from-scratch scoring engine (reports → score → verdict). **Changes
  analyst-visible verdicts** → gated behind a parity backtest.

SP1 consumes today's scoring engine and side-effects as a **black box**.

## Design

### 1. Internal state model + display mapping

Add `Case.lifecycle_state` (indexed) as the authoritative state. `Case.status`
becomes a **derived display value** kept in sync whenever `lifecycle_state`
changes.

| `lifecycle_state` | display `status` | meaning |
|---|---|---|
| `CREATED` | On Going | row exists, nothing dispatched yet |
| `ANALYZING` | On Going | ≥1 pending `CaseAnalyzerJob` |
| `SCORING` | On Going | all jobs terminal, finalisation running |
| `FINALIZED` | Done | verdict computed, side-effects done |
| `CONTESTED` | Challenged | analyst challenged the verdict post-finalise |

`To Do` is retired. The four display labels are unchanged, so UI/API and
existing DB rows stay compatible.

### 2. Transition rules + guard

A single `transition(case, to_state)` helper enforces a legal table and updates
both `lifecycle_state` and the derived `status` atomically:

```
CREATED    → ANALYZING        (first pending job observed)
CREATED    → SCORING          (zero analyzers dispatched — shortcut)
ANALYZING  → SCORING          (last pending job went terminal)
SCORING    → FINALIZED        (finalisation complete; stamps finalized_at)
FINALIZED  → CONTESTED        (analyst challenge)
CONTESTED  → FINALIZED        (challenge resolved)
```

Any other transition raises `IllegalTransition`. `FINALIZED` and `CONTESTED`
are terminal for reconciliation (reconcile short-circuits on them).

### 3. `reconcile_case(case_id)` — the single entrypoint

A Celery task, always async, holding the existing per-case Redis lock
(`case_update_lock:<id>`):

```
reconcile_case(case_id):
  acquire per-case lock (skip if held)
  load case
  if lifecycle_state in {FINALIZED, CONTESTED}: return       # idempotent
  for caj in pending CaseAnalyzerJobs(case): update_single_job(caj)   # sync ledger from Cortex
  if any pending CaseAnalyzerJob remains:
      transition(case, ANALYZING)
  else:
      transition(case, SCORING)
      finalise(case)              # scoring black box + verdict + side-effects
      transition(case, FINALIZED)
  release lock
```

`finalise(case)` wraps today's `get_results` + scoring + side-effects. Zero
report ⇒ verdict `Failure`. It runs **exactly once** per case, guarded by the
`SCORING → FINALIZED` transition and the `finalized_at` stamp.

### 4. Trigger unification

All three triggers collapse to `reconcile_case.delay(case_id)`:

| Old trigger | New |
|---|---|
| webhook `process_cortex_job(case_id, job_id)` | enqueue `reconcile_case(case_id)` |
| cron `update_ongoing_cases` (scans cases **with** a pending job) | scan **all non-terminal** cases (`lifecycle_state ∉ {FINALIZED, CONTESTED}`) → enqueue `reconcile_case` each; **jobless cases now included** |
| dispatch-time (interim inline finalise) | enqueue `reconcile_case(case_id)` after dispatch |

The cron change is what heals zero-analyzer cases going forward; the dispatch
enqueue gives near-immediate finalisation for them.

### 5. Data model + migration + orphan heal

- **Schema:** add `lifecycle_state` (CharField, choices, indexed, default
  `CREATED`) and `finalized_at` (nullable datetime) to `Case`.
- **Data migration:** backfill existing rows — `Done`→`FINALIZED` (+ set
  `finalized_at` from `last_update`), `Challenged`→`CONTESTED`, `On Going`→
  `ANALYZING` if it has a pending job else `CREATED`.
- **Management command `heal_orphaned_cases`:** enqueue `reconcile_case` for
  every non-terminal case, finalising already-stuck ones (e.g. the cases 7/8
  observed in testing). Idempotent; safe to re-run.

### 6. Error handling

- `reconcile_case` is wrapped so a single case's failure is logged and does not
  abort a cron batch (mirrors current cron behaviour).
- Lock contention → skip (another worker/webhook owns the case); the cron
  fallback re-picks it next tick.
- Cortex sync failure inside `update_single_job` leaves the job pending; the
  `fail_stale_jobs` sweep (unchanged) still auto-fails jobs past the stale
  timeout, after which reconcile finalises.

## Testing strategy

- **State machine unit tests:** every legal transition succeeds; representative
  illegal transitions raise; `status` stays in sync with `lifecycle_state`.
- **`reconcile_case` idempotency:** calling twice finalises once (assert one
  `finalized_at`, no duplicate side-effect via a spy).
- **Zero-analyzer:** case with no jobs → `reconcile_case` → `FINALIZED` /
  `Failure` / display `Done`.
- **Pending job:** case with an InProgress job → stays `ANALYZING` / `On Going`.
- **Cron pickup:** a jobless non-terminal case is enqueued by the cron scan.
- **Backfill migration:** rows map to the correct `lifecycle_state`.
- **Legacy test reconciliation:** `cortex_job/tests/test_legacy.py::
  test_empty_results_keep_case_ongoing` encodes the old (buggy) behaviour and is
  rewritten to assert the new terminal outcome. (Also triage the 2 unrelated
  `Mock not iterable` errors surfaced in the combined suite run — confirm
  pre-existing vs. introduced.)

## Rollout

1. Ship schema + data migration.
2. Ship `reconcile_case` + trigger rewiring + state guard.
3. Run `heal_orphaned_cases` once post-deploy to clear existing stuck cases.

No analyst-visible verdict change beyond the zero-analyzer case now resolving to
`Done/Failure` instead of hanging `On Going/Suspicious`.
