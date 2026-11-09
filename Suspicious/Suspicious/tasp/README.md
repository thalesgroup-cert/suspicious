# ⏱️ Tasp — Task scheduling

`tasp` (Tasks And Scheduled Processes) hosts the Celery beat schedule, the thin task wrappers, and the per-cron implementations that drive Suspicious' background work.

> Historical note: this app used to drive `django-crontab`. It now uses Celery + Redis/Valkey. The dependency was swapped during the R1+P1 migration (see `docs/superpowers/specs/2026-04-17-redis-celery-design.md`).

---

## 📦 Overview

`tasp` is responsible for:

- Registering Celery tasks (`tasp.tasks`) — thin wrappers around the per-domain implementations in `tasp.cron.*`.
- Owning the project's Celery beat schedule (declared in `suspicious/settings.py`, executed by the `suspicious_celery_beat` container; the `suspicious_celery` worker runs the tasks).
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
| `sweep-missing-mail-previews` | `tasp.tasks.sweep_missing_mail_previews` | every 600 s | Enqueues `render_mail_preview` (up to 200 per run) for mails that have an archive but no preview yet |
| `check-challengeable` | `tasp.tasks.check_challengeable` | daily 00:00 | Refresh the daily "challengeable" flag |
| `sync-monthly-kpi` | `tasp.tasks.sync_monthly_kpi` | every 300 s | Roll the monthly KPI snapshots |
| `delete-old-reports` | `tasp.tasks.delete_old_reports` | monthly day 1 | GC ageing `AnalyzerReport` rows |
| `purge-old-mail-previews` | `tasp.tasks.purge_old_mail_previews` | daily 03:00 | Deletes mail preview images older than 90 days from the bucket (age only; oversized recent previews are a manual `purge_mail_previews --min-size-mb`) |
| `materialise-dashboard-snapshots` | `tasp.tasks.materialise_dashboard_snapshots` | daily 02:00 | Materialise the dashboard summary tables |

### Connector-registered entries

`connectors/apps.py` adds these to the beat schedule at startup, from the registered connectors:

| Name | Task | Cadence | Purpose |
|---|---|---|---|
| `connector-<name>-<schedule>` | `connectors.tasks.run_connector_sync` | per manifest | One per `Schedule` in a connector manifest, for example `connector-chromadb-cleanup` (86400 s), `connector-watcher-sync` (300 s) and `connector-ai_model-label-sync` (86400 s). Disabled connectors return immediately |
| `ai-model-retrain-check` | `ai_model.tasks.maybe_start_retrain` | every 86400 s | Starts a scheduled retrain when `retrain_enabled` is true and the newest model is older than `retrain_interval_days` |
| `ai-model-materialise-stats` | `ai_model.tasks.materialise_model_stats` | every 86400 s | Daily per-version counters, label purity and warnings for the AI model card |
| `ai-model-server-sync` | `ai_model.tasks.sync_server` | every 300 s | Brings the inference server's loaded models back in line with the registry (for example after a restart) |

The three `ai-model-*` entries exist whenever the `ai_model` connector is registered; each task checks whether the connector is enabled.

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

- Beat lives in its own container, `suspicious_celery_beat`, separate from the `suspicious_celery` worker. Without it no periodic task fires. `make logs s=suspicious_celery_beat` shows the schedule firing; `make logs s=suspicious_celery` shows the tasks running.
- Celery task-level limits are set in `suspicious/celery.py`: `task_time_limit=600`, `task_soft_time_limit=540` (R2).
- All cron implementations accept `OpenTelemetry` spans via the `tasp.cron.*` modules; traces are exported to Tempo when `observability.opentelemetry.enabled` is set in `settings.json` and the monitoring stack under `deployment/docker/monitoring/` is running (see [Monitoring](../../../docs/operations/monitoring.md)).

---

## 📄 License

Apache-2.0 (same as the parent project).
