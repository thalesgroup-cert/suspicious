# 🧳 Cortex Job Module

Django app that orchestrates Cortex analyzers, persists their reports, and links them to the cases they belong to.

---

## 📦 Overview

The `cortex_job` app is responsible for:

- Defining the analyzers and the reports they produce (`Analyzer`, `AnalyzerReport`)
- Mapping each Cortex job to the case(s) that own it (`CaseAnalyzerJob`)
- Dispatching analyzer runs against `CortexJob.run_analyzer` (writes the report and the ledger atomically)
- Looking cases up from a single Cortex job ID via the ledger (powers the `/api/cortex/webhook/` view)
- Providing the manager methods (`update_single_job`, `finalise_case`, `manage_jobs`) used by the webhook task and the cron fallback

---

## 🧩 Directory Structure

```
cortex_job/
├── admin.py
├── apps.py
├── models.py                                  # Analyzer, AnalyzerReport, CaseAnalyzerJob
├── tests/
│   ├── test_caseanalyzerjob_model.py
│   ├── test_run_analyzer_writes_caj.py
│   └── test_backfill_migration.py
├── urls.py
├── views.py
├── migrations/
│   ├── 0008_caseanalyzerjob.py                # New junction table (Cortex case-job mapping)
│   ├── 0009_drop_redundant_caj_indexes.py
│   └── 0010_backfill_caseanalyzerjob.py       # Data migration for live cases
├── cortex_utils/
│   └── cortex_and_job_management.py           # CortexJob, CortexJobManager
```

---

## 🗄️ Schema

### `Analyzer`

One row per Cortex analyzer (cached locally so reports survive a Cortex restart). `analyzer_cortex_id` is the immutable Cortex side identifier; `weight` feeds the score-process aggregation.

### `AnalyzerReport`

One row per Cortex job result. Holds the raw Cortex payload (`report_summary`, `report_full`, `report_taxonomy`), the computed `score`/`confidence`/`level`/`category`, and a single artifact FK (`file`, `url`, `ip`, `hash`, `domain`, `mail`, `mail_body`, or `mail_header`). Indexed on `(type, status, <fk>)` to keep `score_process` queries cheap.

### `CaseAnalyzerJob` *(introduced in `0008_caseanalyzerjob`)*

Per-case ledger of dispatched Cortex jobs. One row per `(case, cortex_job_id)`. Status mirrors `AnalyzerReport.status` but is per-case (`Waiting`, `InProgress`, `Success`, `Failure`, `Deleted`).

- `case` → `case_handler.Case` (`CASCADE` — deleting a case drops its ledger)
- `analyzer` → `Analyzer` (`PROTECT` — keep ledger meaning when a Cortex analyzer is removed)
- `analyzer_report` → `AnalyzerReport` (`SET_NULL` — `delete_old_reports` may GC reports; the ledger outlives)
- `UniqueConstraint(case, cortex_job_id)` — idempotent dispatch and re-runs.
- Indexes: `cortex_job_id` (webhook lookup), `(case, status)` (per-case status check), `(status, created_at)` (stale-rescue scan).

The ledger replaces the legacy 8-FK Q-object that the webhook used to reverse-walk through `Case → fileOrMail / nonFileIocs`: looking up the case for a Cortex job is now a single indexed read.

---

## 🔁 Runtime flow

```
[dispatch]   CortexJob.run_analyzer(api, analyzer, data, data_type, case)
               @transaction.atomic
               ├─ POST Cortex /analyzers/run → job_id
               ├─ INSERT AnalyzerReport (cortex_job_id, artifact FK, status=InProgress)
               └─ INSERT CaseAnalyzerJob (case, cortex_job_id, analyzer_report, status=InProgress)

[webhook]    POST /api/cortex/webhook/  {jobId}
               ├─ HMAC compare_digest against settings.CORTEX_WEBHOOK_SECRET
               ├─ Redis dedup (`cortex_job_processed:<jobId>`, TTL 1 h)
               ├─ SELECT CaseAnalyzerJob WHERE cortex_job_id=jobId AND status IN (Waiting, InProgress)
               └─ for case_id in matches: tasp.tasks.process_cortex_job.delay(case_id, jobId)

[celery]     process_cortex_job(case_id, job_id)
               ├─ acquire per-case Redis lock case_update_lock:<id>
               ├─ skip if CAJ.status not in pending (idempotent on retry)
               ├─ CortexJobManager.update_single_job(caj) → syncs AR + CAJ
               └─ if _case_has_pending_jobs(case_id) == False:
                       CortexJobManager.finalise_case(case)

[cron 300s]  update_ongoing_case_jobs (fallback — covers missed webhook deliveries)
               └─ filter Case WHERE status="On Going" AND has pending CAJ;
                  per-case Redis lock → manage_jobs(case) → save()

[cron 600s]  fail_stale_jobs
               └─ bulk UPDATE CaseAnalyzerJob.status='Failure', completed_at=now()
                  WHERE status IN pending AND created_at < now() - STALE_JOB_TIMEOUT_SECONDS
```

`run_analyzer` is wrapped in `transaction.atomic`. `CortexJob.get_analyzer_db` wraps its own `Analyzer.objects.create` in a nested savepoint so an `IntegrityError` from a concurrent dispatch race never poisons the outer transaction.

---

## ⚙️ Key components

### `models.py`
`Analyzer`, `AnalyzerReport`, `CaseAnalyzerJob`. The latter exposes `STATUS_*` constants and `PENDING_STATUSES = (STATUS_WAITING, STATUS_INPROGRESS)` used by every query in the webhook / cron path.

### `cortex_utils/cortex_and_job_management.py`

- `CortexJob.run_analyzer(api, analyzer, data, data_type, case)` — atomic dispatch.
- `CortexJob.run(api, analyzer, value, data_type, case)` — thin forwarder (kept for `mail_body` legacy hook).
- `CortexJob.launch_cortex_jobs(self, value, data_type, case)` and `launch_cortex_ai_jobs(self, value, data_type, case)` — multi-analyzer dispatch sites. **All callers must thread a non-None `case`**; `run_analyzer` raises `TypeError` otherwise.
- `CortexJobManager.update_single_job(caj)` — sync one CAJ + its AR from Cortex.
- `CortexJobManager.finalise_case(case)` — aggregate per-artifact results, run `generate_description`, then `CortexAnalyzerReports.get_report(case)` if the case flipped to `Done`. Called from `process_cortex_job` once the last pending CAJ for the case transitions out of pending.
- `CortexJobManager.manage_jobs(case)` — unchanged per-case bulk pass, used by the cron fallback.

### `views.py` (registered under `/api/cortex/webhook/`)
HMAC-authenticated webhook entry point. Helper `_find_cases_for_job` is the single source of truth for case lookup; the legacy `_find_case_ids_for_job` Q-object traversal is removed.

---

## 🧪 Testing

Run tests inside the Docker container (the test runner expects the `/app/log` volume to exist; the host-side `_is_test` predicate flips to in-memory SQLite when `/app/log` is missing, so prefer `docker exec`):

```bash
docker exec suspicious bash -c "cd /app/Suspicious && python manage.py test cortex_job -v 2"
```

Targeted suites:

```bash
# Model constraints + cascade behaviour
docker exec suspicious bash -c "cd /app/Suspicious && python manage.py test cortex_job.tests.test_caseanalyzerjob_model"

# Atomic dispatch (run_analyzer writes AR + CAJ rollback semantics)
docker exec suspicious bash -c "cd /app/Suspicious && python manage.py test cortex_job.tests.test_run_analyzer_writes_caj"

# Backfill data migration (0010)
docker exec suspicious bash -c "cd /app/Suspicious && python manage.py test cortex_job.tests.test_backfill_migration"
```

---

## 🔧 Operational notes

- `STALE_JOB_TIMEOUT_SECONDS` is read from `settings.json` → `integrations.cortex.stale_job_timeout_seconds` (default 86400). Tune it to your slowest analyzer (sandbox detonation is the typical upper bound).
- `CORTEX_WEBHOOK_SECRET` (from `integrations.cortex.webhook_secret`) must be set in production; when empty the webhook returns 503 by design.
- Per-case Redis lock key: `case_update_lock:<case_id>`, TTL 120 s.
- jobId dedup key: `cortex_job_processed:<jobId>`, TTL 1 h.

---

## 📌 Migrations

The Cortex Case-Job Mapping redesign lands in three migrations:

| Migration | Purpose |
|---|---|
| `0008_caseanalyzerjob` | Schema: create the `CaseAnalyzerJob` table + indexes + unique constraint |
| `0009_drop_redundant_caj_indexes` | Cleanup: drop duplicate single-col indexes that `db_index=True` + `Meta.indexes` produced |
| `0010_backfill_caseanalyzerjob` | Data: backfill ledger rows for any non-Done cases that existed before the cutover. Re-runnable via `bulk_create(ignore_conflicts=True)` |

Roll forward with `make migrate`. Rollback strategy: revert the deployed image; backfilled CAJ rows are kept (the schema migration is not reversed). A hard rollback is `python manage.py migrate cortex_job 0007`, then drop the table manually.

---

## 📄 License

Apache-2.0 (same as the parent project).
