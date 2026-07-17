# SP2 — Typed Aggregation + Idempotent Finalisation

**Status:** Design approved, pending spec review
**Date:** 2026-07-03
**Part of:** Case-finalisation modernization program (SP1 ✅ → **SP2** → SP3)
**Depends on:** SP1 (lifecycle state machine + `reconcile_case`), merged on `feature/frontweb`.

## Context

SP1 replaced the finalise triggers with one idempotent `reconcile_case` →
`reconcile_case_core` → `finalise()` path and fixed the hang/verdict/dedup
bugs. After SP1, the legacy string-ID-set "buckets" (`CortexJobManager.results`,
populated by `get_results`/`process_*`/`update_results`/`calculate_total_results`)
survive but are **only** consumed by `finalise()` → `_describe()` to build the
case description string. Confirmed: `CortexAnalyzerReports.get_report` (the
scoring/verdict/side-effect path) issues its own `AnalyzerReport` queries and
never touches `self.results`.

Three residual problems from the original SP2 scope remain:

1. **Untyped, redundant aggregation.** ~300 lines of `process_file`/
   `process_mail`/`process_mail_archive`/`process_mail_artifact`/`process_iocs`/
   `update_results`/`calculate_total_results` + a nested dict of `set()`s exist
   to produce six integer counts that only a description string reads. The
   `CaseAnalyzerJob` ledger (added after this machinery) already holds one
   deduped row per (case, cortex job) with exactly the statuses the buckets
   track — the same counts are a single `GROUP BY` away.
2. **KPI double-count.** `update_kpi_and_user_stats` (`score_process/scoring/
   update_handler.py`) unconditionally does `total_cases += 1` and
   `update_case_results(...)` every call. SP1's per-case lock + terminal
   short-circuit make double-finalisation unlikely, but nothing structurally
   prevents a double count.
3. **Fail-dangerous default.** `Case.results` defaults to `SUSPICIOUS`
   (`case_handler/models.py:50`), and `case_creator.py` sets `results="Suspicious"`
   on creation. A case reads "Suspicious" until it is scored.

## Scope

**In:** the aggregation representation feeding `finalise`/`_describe`, KPI
counting idempotency, and the `Case.results` default.

**Out (SP3):** the scoring engine itself (`calculate_final_scores`,
`calculate_result_ranges`, deny-list/malicious-vote), which changes
analyst-visible verdicts and needs a parity backtest.

## Design

### 1. `CaseAggregate` — typed, one query

New module `Suspicious/Suspicious/cortex_job/cortex_utils/aggregate.py`:

```python
from dataclasses import dataclass
from django.db.models import Count
from cortex_job.models import CaseAnalyzerJob


@dataclass(frozen=True)
class CaseAggregate:
    total: int
    success: int
    failure: int
    deleted: int
    in_progress: int
    waiting: int

    @property
    def pending(self) -> int:
        return self.in_progress + self.waiting

    @property
    def scored(self) -> int:
        """Terminal, non-deleted reports — the denominator for descriptions."""
        return self.total - self.deleted


_STATUS_FIELD = {
    CaseAnalyzerJob.STATUS_SUCCESS: "success",
    CaseAnalyzerJob.STATUS_FAILURE: "failure",
    CaseAnalyzerJob.STATUS_DELETED: "deleted",
    CaseAnalyzerJob.STATUS_INPROGRESS: "in_progress",
    CaseAnalyzerJob.STATUS_WAITING: "waiting",
}


def aggregate_case(case) -> CaseAggregate:
    counts = {v: 0 for v in _STATUS_FIELD.values()}
    total = 0
    rows = (
        CaseAnalyzerJob.objects
        .filter(case=case)
        .values("status")
        .annotate(n=Count("id"))
    )
    for row in rows:
        total += row["n"]
        field = _STATUS_FIELD.get(row["status"])
        if field:
            counts[field] = row["n"]
    return CaseAggregate(total=total, **counts)
```

One indexed query per case (hits the existing `(case, status)` index). Deduped
by construction — one `CaseAnalyzerJob` per (case, cortex job). Per-analyzer-type
breakdown is dropped: verified nothing consumes it (only `_describe` read the
buckets, and it read totals).

### 2. Delete the bucket machinery; `finalise`/`_describe` take a `CaseAggregate`

`finalise()` (`reconciliation.py`) drops `mgr.get_results(case)` and instead:

```python
def finalise(case) -> None:
    agg = aggregate_case(case)
    CortexAnalyzerReports.get_report(case)   # scoring/verdict/side-effects (SP3-owned)
    case.description = _describe(agg)
    case.save()
```

`_describe(agg: CaseAggregate) -> str` rewritten to read the dataclass:

```python
def _describe(agg: CaseAggregate) -> str:
    if agg.scored == 0:
        return ("No analyzer was applicable to this submission, so it could "
                "not be analysed. Check that the relevant Cortex analyzers "
                "are enabled.")
    if agg.failure == 0:
        return "All analyzers completed successfully. You can now view the full results."
    if agg.success == 0:
        return "All analyzers failed to run. Please check the configuration and retry."
    return (f"{agg.success}/{agg.scored} analyzers succeeded. "
            "Consider rerunning the rest for a complete analysis.")
```

**Delete from `CortexJobManager`** (verified only reachable via `get_results`):
`get_results`, `process_file`, `process_mail`, `process_mail_archive`,
`process_mail_artifact`, `process_iocs`, `update_results`,
`calculate_total_results`, and the `self.results` init block in `__init__`.
Each deletion is gated on a grep confirming zero remaining callers outside the
deleted set and tests. Keep `update_single_job`, `get_cortex_jobs_results`,
`launch_cortex_jobs`, and the Cortex-API helpers.

**Name-collision warning:** the methods to delete are the **`CortexJobManager`**
bucket-populating ones. They share names with unrelated, still-used functions in
`score_process/scoring/processing.py` (`process_file_ioc`, `process_mail`,
`process_ioc`) that `get_report` calls — those MUST be kept. Delete only the
`CortexJobManager` methods; verify each caller path before removing.

### 3. Idempotent KPI counting

Add `Case.kpi_counted = BooleanField(default=False)` (migration). Rewrite
`update_kpi_and_user_stats`:

```python
def update_kpi_and_user_stats(case):
    from django.db import transaction
    with transaction.atomic():
        locked = Case.objects.select_for_update().get(pk=case.pk)
        if locked.kpi_counted:
            return
        # ... existing KPI + per-user increments ...
        locked.kpi_counted = True
        locked.save(update_fields=["kpi_counted"])
        case.kpi_counted = True
```

Exactly-once per case regardless of how many times finalisation runs. (Challenge
→ resolve does not re-count.)

### 4. Sane `Result` default

- `Case.results` default `Result.SUSPICIOUS` → `Result.INCONCLUSIVE` (migration —
  `AlterField`; existing rows keep their stored value, only new-row default
  changes).
- `case_creator.py` create path: `results="Suspicious"` → `"Inconclusive"`.
- Leave `results_ai` / `category_ai` defaults untouched (AI-classifier domain,
  out of scope).

## Data flow (after SP2)

```
reconcile_case_core(case)
  └─ finalise(case)
       ├─ agg = aggregate_case(case)          # one GROUP BY over CaseAnalyzerJob
       ├─ get_report(case)                     # scoring/verdict/side-effects (SP3)
       │    └─ update_kpi_and_user_stats(case) # now idempotent
       ├─ case.description = _describe(agg)
       └─ case.save()
```

## Error handling

- `aggregate_case` is a pure read; a DB error propagates to `finalise` →
  `reconcile_case` (which now logs-and-swallows per case, SP1 `0539a31`).
- KPI `select_for_update` runs inside the per-case Redis lock already held by
  `reconcile_case`, so lock contention is not newly introduced.

## Testing strategy

- **`aggregate_case`:** a case with a mix of Waiting/InProgress/Success/Failure/
  Deleted `CaseAnalyzerJob` rows returns the right counts; `pending`/`scored`
  derived correctly; zero-job case → all zeros.
- **`_describe`:** each branch (no-scored / all-success / all-failure / partial)
  from a constructed `CaseAggregate` (no DB, no mocks-of-buckets).
- **KPI idempotency:** call `update_kpi_and_user_stats` twice → `total_cases`
  increments once; `kpi_counted` set.
- **Default:** a freshly created `Case` reads `results == "Inconclusive"`.
- **Regression:** existing `finalise`/`reconcile_core` tests stay green after the
  bucket machinery is deleted (they mock `get_report`, so they exercise the new
  aggregate path).
- **Dead-code sweep:** grep confirms no live references to the deleted methods.

## Rollout

Two migrations (`kpi_counted` add, `results` default alter) — both additive/
metadata-only, no data backfill. No analyst-visible change except cases showing
"Inconclusive" instead of "Suspicious" before scoring.
