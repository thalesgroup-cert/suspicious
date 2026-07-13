# ⏱️ Tasp — Task scheduling

`tasp` (Tasks And Scheduled Processes) hosts the Celery beat schedule, the thin task wrappers, and the per-cron implementations that drive Suspicious' background work.

> Historical note: this app used to drive `django-crontab`. It now uses Celery + Redis/Valkey. The dependency was swapped during the R1+P1 migration (see `docs/superpowers/specs/2026-04-17-redis-celery-design.md`).

---

## 📦 Overview

`tasp` is responsible for:

- Registering Celery tasks (`tasp.tasks`) — thin wrappers around the per-domain implementations in `tasp.cron.*`.
- Owning the project's Celery beat schedule (declared in `suspicious/settings.py`, executed by `suspicious_celery`).
- Providing per-case Redis lock conventions used by both the webhook and the cron fallback.

---

## 🧩 Directory structure

```
tasp/
├── apps.py
├── tasks.py                   # @shared_task wrappers
├── tests/
│   ├── test_celery_wrappers.py
│   ├── test_finalise_case_idempotent.py
│   ├── test_process_cortex_job.py
│   ├── test_fail_stale_jobs.py
│   └── test_update_ongoing_skips_no_pending.py
└── cron/
    ├── fetch_emails.py
    ├── sync_cortex.py
    ├── user_and_cases.py      # update_ongoing_case_jobs, sync_user_profiles
    ├── suspicious.py
    ├── kpi.py
    ├── cleanup.py
    ├── watcher.py
    └── dashboard_snapshot.py
```

---

## ⏰ Beat schedule (`suspicious/settings.py`)

| Name | Task | Cadence | Purpose |
|---|---|---|---|
| `fetch-emails` | `tasp.tasks.fetch_emails` | every 60 s | IMAP poll, ingest reported phish |
| `sync-cortex` | `tasp.tasks.sync_cortex` | every 60 s | Mirror the Cortex analyzer catalogue into the local `Analyzer` table |
| `update-ongoing-cases` | `tasp.tasks.update_ongoing_cases` | every 300 s | Fallback for missed Cortex webhook deliveries. Skips cases with no pending `CaseAnalyzerJob` via an `Exists()` annotation |
| `fail-stale-jobs` | `tasp.tasks.fail_stale_jobs` | every 600 s | Auto-fails `CaseAnalyzerJob` rows whose `created_at` is older than `STALE_JOB_TIMEOUT_SECONDS` |
| `sync-user-profiles` | `tasp.tasks.sync_user_profiles` | every 600 s | Pull profile updates from LDAP/OIDC |
| `watcher-sync` | `tasp.tasks.watcher_sync` | every 300 s | Run the WatcherLegitDomain / WatcherMonitoredDomain reconciliation |
| `check-challengeable` | `tasp.tasks.check_challengeable` | daily 00:00 | Refresh the daily "challengeable" flag |
| `sync-monthly-kpi` | `tasp.tasks.sync_monthly_kpi` | every 300 s | Roll the monthly KPI snapshots |
| `delete-old-reports` | `tasp.tasks.delete_old_reports` | monthly day 1 | GC ageing `AnalyzerReport` rows |
| `remove-old-emails` | `tasp.tasks.remove_old_emails` | daily 00:00 | Purge stale `.eml` files from the working dir |
| `materialise-dashboard-snapshots` | `tasp.tasks.materialise_dashboard_snapshots` | daily 02:00 | Materialise the dashboard summary tables |

All wrappers use `@shared_task(bind=True, max_retries=3, acks_late=True)` with exponential-backoff retry on unexpected exception (60 s base for slow tasks, 30 s for the per-job Cortex update).

### Webhook-triggered task

`tasp.tasks.process_cortex_job(case_id, job_id)` is **not on the beat schedule** — it is enqueued by `api.views.cortex_webhook` whenever Cortex POSTs `/api/cortex/webhook/`. It acquires the per-case Redis lock `case_update_lock:<case_id>` (TTL 120 s), syncs the single (case, cortex_job_id) pair, and calls `CortexJobManager.finalise_case` when the case's pending-CAJ count reaches zero. The legacy `process_cortex_webhook_case` task was removed; see `tasp.tasks` for the current signature.

---

## 🔐 Redis lock conventions

- `case_update_lock:<case_id>` — 120 s TTL. Acquired by both `process_cortex_job` and `update_ongoing_case_jobs`; serialises any concurrent updates for the same case.
- `cortex_job_processed:<jobId>` — 1 h TTL. Webhook-level idempotency; duplicate Cortex retries short-circuit.

Both use `django.core.cache.add(...)` so the operation is atomic on the Valkey backend.

---

## 🧪 Testing

```bash
# Run only the new task tests (avoid the legacy in-tests/ collision):
docker exec suspicious bash -c "cd /app/Suspicious && python manage.py test \
    tasp.tests.test_finalise_case_idempotent \
    tasp.tests.test_process_cortex_job \
    tasp.tests.test_fail_stale_jobs \
    tasp.tests.test_update_ongoing_skips_no_pending"
```

The legacy `tasp/tests.py` (now exposed as `tasp.tests.test_celery_wrappers` once moved into the package) predates the Django/Celery integration and has known stale failures — these are not introduced by current work.

---

## 📌 Notes

- Beat lives in the `suspicious_celery` container. `make logs s=suspicious_celery` to watch the schedule fire.
- Celery task-level limits are set in `suspicious/celery.py`: `task_time_limit=600`, `task_soft_time_limit=540` (R2).
- All cron implementations accept `OpenTelemetry` spans via the `tasp.cron.*` modules; traces are exported to Tempo when `make monitor-up` is enabled.

---

## 📄 License

Apache-2.0 (same as the parent project).
