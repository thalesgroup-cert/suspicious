# Move `AnalyzerReport.report_full` to a side table

## Problem
`AnalyzerReport.report_full` is the raw Cortex output. On the dev database
(2,522 reports) it is 99% of the table's bytes:

| column | total | average |
|---|---|---|
| `report_full` | 29.7 MB | 12.4 KB (max 2.7 MB) |
| `report_summary` | 0.3 MB | 121 B |
| `report_taxonomy` | n/a | 101 B |

Two analyzers dominate: `Lookyloo_Screenshot` (230 KB average, a base64
screenshot that is also copied to MinIO) and `Mnemonic_pDNS_Public`
(47 KB). Prod size is bounded by the 30-day cleanup
(`tasp/cron/cleanup.py::delete_old_analyzer_reports`), so it grows with
report volume, not forever.

Django loads every column unless told otherwise, so any `AnalyzerReport`
query that does not defer `report_full` drags the blob over the wire. The
2026-10-07 quick fixes defer it on the admin changelist and the
investigation detail query. Every other path still loads it, and the next
new query will too, unless someone remembers.

## Goals
- `AnalyzerReport` rows become small (about 0.5 KB); the blob lives in
  `AnalyzerReportFull` and is read only by code that needs it.
- No behaviour change for callers: `report.report_full` still returns the
  parsed JSON.
- Zero-downtime rollout in three releases (expand, backfill, contract).

## Non-goals
- Changing what Cortex returns, or compressing the JSON.
- Stripping the base64 screenshot out of `report_full` (a separate, cheaper
  win: the screenshot is already stored in MinIO via `screenshot_key`).
- Changing the 30-day retention.

## Design

### 1. Model
```python
class AnalyzerReportFull(models.Model):
    report = models.OneToOneField(
        AnalyzerReport, on_delete=models.CASCADE, related_name="full", primary_key=True,
    )
    data = models.JSONField()
```
The primary key is the report id, so lookups are one index probe and the
retention delete cascades with the report.

### 2. Compatibility property
`AnalyzerReport.report_full` becomes a property:

- getter: returns `self.full.data` (the related row), or `None` when there
  is none;
- setter: stores the value for `save()` to write through to the side row
  (create or update).

Callers that read `report.report_full` keep working unchanged. Bulk readers
opt in to the join with `select_related("full")` (`reports_for_case` gets a
`with_full=True` flag, default `False`; the callers that read the blob pass
it). A reader that forgets `select_related` pays one query per report, the
same cost as touching a deferred field today, but only on the code path that
actually needs the blob.

### 3. Call sites (the full list, from `grep report_full`)
| site | change |
|---|---|
| `cortex_job/cortex_utils/cortex_and_job_management.py` create (~358) and update (~739) | write through the property; replace `updated_fields.append("report_full")` (not a real column after the contract release) with a save of the side row |
| `score_process/scoring/cortex_analyzers/reports.py`, `enrichment/registry.py`, `screenshots/registry.py`, `cortex_job/cortex_utils/derived_observables.py`, `case_handler/campaigns.py`, `api/utils/observable_report.py`, `connectors/contrib/ai_narration/adapters.py` | read through the property; add `select_related("full")` to the query that feeds them |
| `api/serializers/submissions.py` | the `report_full` field reads the property; its queryset gets `select_related("full")` |
| `cortex_job/admin.py` | remove `report_full` from `_LIST_DEFER` (no longer a column); the change form reads it through the property; resource export keeps `report_full` via a custom field |
| `api/utils/analyzer_reports.py` | `defer_full` becomes `with_full`; default off |

### 4. Rollout: three releases
1. **Expand.** Create `AnalyzerReportFull`. Writers write both the old
   column and the side row (dual-write). Readers still read the column.
2. **Backfill and switch reads.** Management command
   `backfill_report_full [--batch 500]`: copy `report_full` into the side
   table for rows that have none, in primary-key batches, resumable (skips
   rows already copied), safe to re-run. Then flip readers to the property
   and stop writing the column.
3. **Contract.** After a full retention window (30 days) with no reads of
   the column, drop `AnalyzerReport.report_full` in a migration. Because
   cleanup deletes reports after 30 days, a faster option is to let old rows
   age out instead of backfilling all of them.

### 5. Why this also helps deletes
`delete_old_analyzer_reports` runs `AnalyzerReport.objects.filter(...).delete()`.
The model has cascading relations (`DerivedObservable`, `CaseAnalyzerJob`
with `SET_NULL`), so Django must load the instances before deleting them.
Today that loads every `report_full` into worker memory. With the side table
the loaded rows are small; the blobs are removed by the database cascade.

## Testing
- Property: getter with and without a side row, setter creates and updates
  the side row, `save()` persists both in one transaction.
- Dual-write and write-through: creating and updating a report from a
  Cortex payload writes the column and the side row (release 1) and only the
  side row (release 2).
- `backfill_report_full`: copies only missing rows, is idempotent, handles
  an empty table, and handles `report_full` values of `{}` and large JSON.
- Query counts: `assertNumQueries` on the investigation detail, submission
  detail and scoring paths proves `select_related("full")` removes the
  per-report query.
- The existing `cortex_job`, `score_process`, `api` and `connectors`
  suites must pass unchanged at the end of each release.

## Risks
- **N+1 on the read path:** a caller that omits `select_related("full")`
  silently issues one query per report. Mitigated by the query-count tests
  and by `with_full` being explicit in `reports_for_case`.
- **Dual-write drift in release 1:** the two copies can diverge if a write
  path is missed. The backfill compares and repairs; the call-site table
  above is the checklist.
- **Backfill load on prod:** 500-row batches with a short sleep; run off
  peak. Blob rows are large, so watch replication lag if the R6 replica is
  enabled.
- **Gain depends on what is slow:** the quick fixes already removed the blob
  from the admin and investigation detail pages. Before building this,
  re-measure prod (slow-query log, `EXPLAIN`) after that release ships. If
  the remaining cost is mostly the screenshot payload, stripping it from
  `report_full` is a one-file change and may be enough on its own.
