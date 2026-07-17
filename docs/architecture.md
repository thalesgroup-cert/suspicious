# Architecture

Suspicious is a set of containerised services coordinated by a Django REST API
and a Celery worker.

## Services

| Service | Role |
|---|---|
| `suspicious` | Django REST API (Gunicorn, port 9020) |
| `suspicious_celery` | Celery beat + worker (background jobs, cortex sync, case finalisation) |
| `suspicious_ui` | React/Vite frontend (Nginx, port 9021) |
| `db_suspicious` | MariaDB 12 (primary; opt-in replica via R6 router) |
| `redis_broker` / `redis_cache` | Valkey 9 — Celery broker + Django cache |
| `elasticsearch` | Search and indexing |
| `rustfs` | S3-compatible object storage (artifacts/attachments) |
| `cortex` | Analyzer execution engine (YARA, AI, sandbox) |
| `chromadb` | Vector DB for semantic similarity search |
| `feeder` | IMAP poller that auto-ingests emails (container `email_feeder`) |
| `traefik` | Reverse proxy with TLS termination |
| `tempo` / `grafana` | Optional OpenTelemetry trace store + dashboards (manual setup under `deployment/docker/monitoring/`) |

## Request / Analysis flow

1. A user submits an email/file/URL/IP/hash via the web UI, API, or the email
   feeder's IMAP polling.
2. Django creates a `Case`, then dispatches Cortex analyzers via
   `CortexJob.run_analyzer` — each call writes an `AnalyzerReport` *and* a
   `CaseAnalyzerJob` ledger row atomically (`case_id ↔ cortex_job_id`).
3. Cortex runs analyzers asynchronously and POSTs to `/api/cortex/webhook/`
   (HMAC-signed, jobId-deduped) as each job finishes.
4. The webhook view looks up the case via a single indexed read on
   `CaseAnalyzerJob`, then enqueues `process_cortex_job(case_id, job_id)` on
   Celery; the task takes a per-case Redis lock, updates the ledger, and calls
   `finalise_case` once all pending jobs are non-pending.
5. `finalise_case` aggregates scores (Safe / Inconclusive / Suspicious /
   Dangerous), pushes to TheHive/MISP if configured, queries ChromaDB for
   similar past cases, notifies the reporter by SMTP, and updates dashboard KPIs.
6. Celery beat runs `update_ongoing_cases` every 300s as a webhook fallback,
   and `fail_stale_jobs` every 600s to auto-fail jobs pending beyond the
   stale-job timeout.

## URL analysis planning

URLs extracted from a reported email are not all dispatched blindly. At
dispatch time (step 2, mail path only), `plan_url_analysis` collapses equivalent
URLs by canonical key, reuses recent results across cases within
`reuse_ttl_days`, and caps analysis per registered domain to the most
interesting URLs. Every extracted URL is still recorded — capped ones are marked
`skipped` and stay analyzable on demand via
`POST /api/submissions/<id>/urls/<url_id>/analyze/`. The planner is fail-open
(any error → analyze the URL) and kill-switched by `url_analysis.enabled`.
Direct single-URL submission bypasses it. See
[Observable Processors](components/backend/observable-processors.md#url-analysis-planner-url_process).

See [Components](components/backend/index.md) for each part in detail, and the
[API Reference](reference/rest-api.md) for endpoints.
