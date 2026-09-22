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
├── services/
│   └── challenge.py           # reporter challenge-a-verdict workflow
├── tests/                     # tests/test_reconcile_task.py, test_fail_stale_jobs.py, etc.
└── cron/
    ├── fetch_emails.py
    ├── sync_cortex.py
    ├── user_and_cases.py      # update_ongoing_cases, sync_user_profiles
    ├── suspicious.py
    ├── kpi.py
    ├── cleanup.py
    ├── prefix_source.py
    └── dashboard_snapshot.py
```

`cron/watcher.py` no longer lives here — Watcher domain-list reconciliation moved to
`connectors/contrib/watcher/` and is scheduled by the connectors framework's own
`Schedule` mechanism, not a `tasp` beat entry. See
[Connectors](../connectors/README.md).

---

## ⏰ Beat schedule (`suspicious/settings.py`)

| Name | Task | Cadence | Purpose |
|---|---|---|---|
| `fetch-emails` | `tasp.tasks.fetch_emails` | every 60 s | IMAP poll, ingest reported phish |
| `sync-cortex` | `tasp.tasks.sync_cortex` | every 60 s | Mirror the Cortex analyzer catalogue into the local `Analyzer` table |
| `update-ongoing-cases` | `tasp.tasks.update_ongoing_cases` | every 300 s | Fallback for missed Cortex webhook deliveries. Skips cases with no pending `CaseAnalyzerJob` via an `Exists()` annotation |
| `fail-stale-jobs` | `tasp.tasks.fail_stale_jobs` | every 600 s | Auto-fails `CaseAnalyzerJob` rows whose `created_at` is older than `STALE_JOB_TIMEOUT_SECONDS` |
| `sync-user-profiles` | `tasp.tasks.sync_user_profiles` | every 600 s | Pull profile updates from LDAP/OIDC |
| `check-challengeable` | `tasp.tasks.check_challengeable` | daily 00:00 | Refresh the daily "challengeable" flag |
| `sync-monthly-kpi` | `tasp.tasks.sync_monthly_kpi` | every 300 s | Roll the monthly KPI snapshots |
| `delete-old-reports` | `tasp.tasks.delete_old_reports` | monthly day 1 | GC ageing `AnalyzerReport` rows |
| `materialise-dashboard-snapshots` | `tasp.tasks.materialise_dashboard_snapshots` | daily 02:00 | Materialise the dashboard summary tables |

All wrappers use `@shared_task(bind=True, max_retries=3, acks_late=True)` with exponential-backoff retry on unexpected exception (60 s base for slow tasks, 30 s for the per-job Cortex update).

### Webhook-triggered task

`tasp.tasks.reconcile_case(case_id)` is **not on the beat schedule** — it is enqueued by `api.views.cortex_webhook` whenever Cortex POSTs `/api/cortex/webhook/` (and is also what `update_ongoing_cases` falls back to). It acquires the per-case Redis lock `case_update_lock:<case_id>` (TTL 120 s) and calls `reconcile_case_core` (`cortex_job/cortex_utils/reconciliation.py`) — the single entrypoint that syncs the `CaseAnalyzerJob` ledger and advances the case's lifecycle state machine, emitting a `case_finalised` connector event once the case reaches its terminal state. This is a straight rename from an earlier `process_cortex_job`/`finalise_case` pair; nothing by those names exists anymore.

---

## 🔐 Redis lock conventions

- `case_update_lock:<case_id>` — 120 s TTL. Acquired by `reconcile_case`; serialises any concurrent updates for the same case.
- `cortex_job_processed:<jobId>` — 1 h TTL. Webhook-level idempotency; duplicate Cortex retries short-circuit.

Both use `django.core.cache.add(...)` so the operation is atomic on the Valkey backend.

---

## 🧪 Testing

```bash
docker exec suspicious bash -c "cd /app/Suspicious && python manage.py test tasp"
```

`tasp/tests/test_legacy.py` predates the Celery integration; everything else in `tasp/tests/` targets the current task/cron implementations directly.

---

## 📌 Notes

- Beat lives in the `suspicious_celery` container. `make logs s=suspicious_celery` to watch the schedule fire.
- Celery task-level limits are set in `suspicious/celery.py`: `task_time_limit=600`, `task_soft_time_limit=540` (R2).
- All cron implementations accept `OpenTelemetry` spans via the `tasp.cron.*` modules; traces are exported to Tempo when `make monitor-up` is enabled.

---

## 📄 License

Apache-2.0 (same as the parent project).
