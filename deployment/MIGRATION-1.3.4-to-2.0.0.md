# Migration Guide — Suspicious 1.3.4 → 2.0.0

This is a **major** upgrade. It is **not** a drop-in `make deploy`. Plan a
maintenance window: there are slow, one-way data migrations and the background
scheduler is replaced (`django-crontab` → Celery), which requires new Redis
services to be running *before* the web container starts.

Run every step from `deployment/` unless noted.

---

## 0. What changed (read before you touch anything)

| Area | 1.3.4 | 2.0.0 | Impact |
|---|---|---|---|
| Scheduler | `django-crontab` (`suspicious_cron`) | Celery beat + worker (`suspicious_celery`) | Old container retired, new one added |
| Broker / cache | none | Valkey 9 `redis_broker` + `redis_cache` | New mandatory services |
| Django | 5.x | **6.0.5** | Major framework bump (images rebuilt) |
| Auth | django-rest-knox 4.2.0 | **5.0.4** | Token store changed → users likely must re-login |
| Cortex callback | poll/sync | HMAC-signed webhook `/api/cortex/webhook/` | New shared `webhook_secret` required |
| Cortex ledger | implicit | `CaseAnalyzerJob` junction table | Backfill migration (slow) |
| Case artifacts | 5 M2M tables (`FileInCases`, `HashInCases`, `UrlInCases`, `IpInCases`, `MailInCases`) | single `CaseArtifact` model | Consolidation data migration (slow, one-way) |
| Case fields | camelCase columns | snake_case columns | Column rename migration |
| Mail preview | `eml2png` | `imgkit` + bundled `wkhtmltopdf` | Renderer swap (in image) |
| SPA config | baked at build time | runtime `window.__ENV__` from `suspicious-ui/.env` | New env file required |
| Images | local build / old tags | GHCR (`SUSPICIOUS_*_VERSION`) | Pull instead of build |
| Observability | Prometheus + Grafana (`compose_monitoring.yaml`, `make monitor-up`) | Tempo + OTel traces | Old monitoring stack removed |
| DB read replica | none | optional MariaDB replica (R6 router) | Opt-in |

> **One-way migrations.** `0012_consolidate_case_artifacts` and
> `0010_backfill_caseanalyzerjob` rewrite/aggregate data. Your only rollback is
> the DB backup from Step 1. Do not skip the backup.

---

## 1. Pre-flight — back up everything

```bash
make backup-db                       # MariaDB → ./backups/<timestamp>.sql.gz
# Snapshot object + vector stores too. Volumes are prefixed with the compose
# project name (`suspicious`); both mount at /data:
docker run --rm -v suspicious_rustfs_data:/data -v "$PWD/backups":/b alpine \
  tar czf /b/rustfs-$(date +%F).tgz -C /data .
docker run --rm -v suspicious_chromadb_data:/data -v "$PWD/backups":/b alpine \
  tar czf /b/chromadb-$(date +%F).tgz -C /data .
```

> Verify names against your host with `docker volume ls | grep suspicious`.
> The MariaDB volume is `suspicious_db_suspicious_data` (already dumped by
> `make backup-db`).

Confirm the dump is non-empty before continuing. Announce the maintenance
window — analysis is paused from here until Step 9.

---

## 2. Get the 2.0.0 code

```bash
git fetch --tags
git checkout v2.0.0            # or the 2.0.0 release branch
make install-hooks            # optional: wire Conventional-Commits hook
```

---

## 3. Update `deployment/.env`

Diff against `deployment/.env.example` and add the new keys:

```ini
# Image versions (UI/feeder fall back to SUSPICIOUS_VERSION when blank)
SUSPICIOUS_VERSION=2.0.0
SUSPICIOUS_UI_VERSION=
SUSPICIOUS_FEEDER_VERSION=

# New Valkey services
REDIS_BROKER_VERSION=9-alpine
REDIS_CACHE_VERSION=9-alpine

# Read replica (only if you opt into R6 in Step 10 — otherwise leave default)
REPL_USER=replicator
REPL_PASSWORD=CHANGE_ME_replication_password
```

Run `make check-secrets` to confirm no placeholder secrets remain.

---

## 4. Create the SPA runtime config (NEW)

The UI is now one image configured per-deploy at container start (no rebuild).

```bash
cp ../suspicious-ui/.env.example ../suspicious-ui/.env
# edit VITE_API_BASE, VITE_COMPANY_NAME/LOGO, VITE_SUSPICIOUS_EMAIL, docs URLs…
```

Compose loads this as `env_file` and injects it into `window.__ENV__`.

---

## 5. Update `Suspicious/settings.json`

Add the Cortex webhook secret (compare with `settings-sample.json`):

```jsonc
"cortex": {
  "...": "...",
  "webhook_secret": "<long-random-shared-secret>"   // NEW — HMAC
}
```

**Set the identical secret on the Cortex side** so its webhook POSTs to
`/api/cortex/webhook/` verify. Mismatch = every job silently rejected.

(Optional, only with Step 10) add the replica block:

```jsonc
"database": {
  "...": "...",
  "replica": {
    "host": "db_suspicious_replica", "port": 3306,
    "user": "suspicious", "password": "<password>", "name": "db_suspicious"
  },
  "replica_read_apps": ["dashboard", "case_handler"]
}
```

---

## 6. Pull the 2.0.0 images

```bash
make pull          # GHCR: suspicious, suspicious_ui, suspicious_celery, feeder
```

---

## 7. Start the new infra services FIRST

Redis must be live before migrations/web (cache + per-case lock + jobId dedup):

```bash
docker compose up -d redis_broker redis_cache
```

---

## 8. Run database migrations (the slow part)

```bash
make migrate
```

This applies, in order:

- `case_handler` 0009–0013 — camelCase→snake_case rename, index churn,
  **`0012_consolidate_case_artifacts`** (copies all 5 M2M tables into
  `CaseArtifact`, dedupes, then drops the old tables/constraints).
- `cortex_job` 0006–0010 — new `CaseAnalyzerJob` table +
  **`0010_backfill_caseanalyzerjob`** (rebuilds the case↔job ledger for every
  non-`Done` case; iterates in 1000-row chunks).
- `dashboard` 0005–0006 — `DashboardSnapshot` + index.
- `mail_feeder` 0014–0016 — index cleanup + `0016_mail_preview_minio_explicit`.
- `profiles` 0009 — theme field change.

> On a large DB the two data migrations can run for many minutes. Run inside the
> downtime window; do not interrupt. Then:

```bash
make collectstatic
```

### Mail-preview backfill (automatic)

`0016_mail_preview_minio_explicit` adds `Mail.preview_object_key`; existing
rows start blank, so old cases show "No preview" until re-rendered. This now
self-heals: the `sweep-missing-mail-previews` Celery beat task (every 600s)
enqueues `render_mail_preview` for any fetchable mail missing a preview, once
`suspicious_celery` is up (Step 9). No manual step required.

For an immediate, operator-paced backfill instead of waiting on the sweeper:

```bash
make shell
python manage.py regenerate_mail_previews            # missing only
python manage.py regenerate_mail_previews --dry-run  # preview the plan
```

> Mails whose `MailArchive` has an empty `bucket_name` (e.g. some web-UI
> submissions) are not fetchable from MinIO and are skipped by both the
> sweeper and the command; their preview is produced inline at ingestion.

---

## 9. Recreate services — retire cron, bring up Celery

The `suspicious_cron` container is gone. Force-recreate so the new compose
topology (Celery, Redis deps, GHCR images, SPA env) takes effect:

```bash
docker compose rm -sf suspicious_cron 2>/dev/null || true   # remove old scheduler
make redeploy                                                # force-recreate all
```

`make redeploy` runs `up -d --force-recreate --remove-orphans`, which also
sweeps the orphaned cron container if the manual `rm` was skipped.

---

## 10. (Optional) Read replica — R6

```bash
make db-replica-init     # one-time; needs REPL_PASSWORD; wipes replica volume
make replica-up
make replica-status      # check Slave_IO_Running=Yes, Seconds_Behind_Master
```

Only after the replica is healthy, keep the `database.replica` block from Step 5
so `dashboard` + `case_handler` reads route to it.

---

## 11. (Optional) Observability — Tempo / OTel

`make monitor-up` (Prometheus/Grafana) **no longer exists**. Traces now go to
Tempo via the OpenTelemetry SDK. To enable, set the OTel exporter env on
`suspicious` + `suspicious_celery` + feeder and start the Tempo/Grafana stack
under `deployment/docker/monitoring/`.

---

## 12. Verify

```bash
make status                                   # all healthy, suspicious_celery present, no suspicious_cron
curl -fsS https://<host>/api/health/          # pings DB + Redis (R9)
docker compose exec suspicious_celery celery -A suspicious inspect ping
```

Then exercise the changed paths:

1. **Login** — Knox 4→5 may have invalidated existing tokens; confirm a fresh login works and old sessions re-auth cleanly.
2. **Cortex round-trip** — submit a sample, confirm a job reaches
   `/api/cortex/webhook/` and the case finalises (validates `webhook_secret`).
3. **Mail preview** — open a case with an email; confirm the preview renders
   (validates `imgkit`/`wkhtmltopdf` replacing `eml2png`).
4. **Dashboard KPIs** — confirm snapshots populate.
5. **Scheduled tasks** — confirm beat runs `update_ongoing_cases` (~300s) and
   `fail_stale_jobs` (~600s) in the `suspicious_celery` logs.

---

## 13. Rollback

If a data migration or verification fails:

```bash
make down
make restore-db f=backups/<timestamp>.sql.gz   # restore pre-migration DB
# restore rustfs/chromadb tarballs to their volumes if they changed
git checkout v1.3.4
make pull && make up
```

Because `0012`/`0010` are one-way, **restoring the DB backup is the rollback** —
there is no `migrate` reverse path for the consolidation.
