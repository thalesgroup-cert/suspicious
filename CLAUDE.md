# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is Suspicious?

Suspicious is an AI-powered phishing and threat-analysis platform built by Thales Group CERT. It automatically inspects, classifies, and reports suspicious emails, files, URLs, IPs, and file hashes. Analysis combines static YARA rules, an ML email classifier (AIMailAnalyzer), sandboxing, metadata inspection, and integrations with Cortex, TheHive, MISP, Elasticsearch, and LDAP.

## Commands

### Deployment (from `deployment/`)

```bash
make init               # First-time setup: network, TLS certs, config dirs
make up                 # Start all services
make build              # Rebuild Docker images
make deploy             # Zero-downtime rolling update (pull → migrate → restart)
make migrate            # Run Django DB migrations
make createsuperuser    # Create Django admin user
make collectstatic      # Collect Django static files
make logs [s=<svc>]     # Follow logs (all services or specific)
make status             # Show container health
make shell              # Bash into the web container
make db-shell           # Open MariaDB shell
make backup-db          # Backup MariaDB
make restore-db f=<file>
make monitor-up         # Enable Tempo + Grafana (OpenTelemetry traces, port 3000)
```

### Frontend (`suspicious-ui/`)

```bash
pnpm install
pnpm dev          # Vite dev server on port 5173
pnpm build        # Production build
pnpm lint         # ESLint check
pnpm lint:fix     # ESLint auto-fix
pnpm test         # Vitest unit tests
pnpm test:ui      # Interactive test UI
pnpm test:e2e     # Playwright end-to-end tests
```

### Backend (`Suspicious/`)

```bash
python manage.py migrate
python manage.py test
python manage.py createsuperuser
```

## Architecture

### Services (Docker Compose)

| Service | Role |
|---|---|
| `suspicious` | Django REST API (Gunicorn, port 9020) |
| `suspicious_celery` | Celery beat + worker (background jobs, cortex sync, case finalisation) |
| `suspicious_ui` | React/Vite frontend (Nginx, port 9021) |
| `db_suspicious` | MariaDB 12 (primary read/write; opt-in replica via R6 router) |
| `redis_broker` / `redis_cache` | Valkey 9 — Celery broker + Django cache (per-case lock, webhook jobId dedup) |
| `elasticsearch` | Search and indexing |
| `rustfs` | MinIO-compatible S3 object storage (artifacts/attachments) |
| `cortex` | Analyzer execution engine (YARA, AI, sandbox); reports back via HMAC-signed webhook |
| `chromadb` | Vector DB for semantic similarity search |
| `email_feeder` | IMAP poller that auto-ingests emails (runs as non-root `feeder` UID) |
| `traefik` | Reverse proxy with TLS termination |
| `tempo` / `grafana` (optional) | OpenTelemetry trace store + dashboards, started via `make monitor-up` |

### Request / Analysis Flow

1. User submits email/file/URL/IP/hash via web UI, API, or the email feeder's IMAP polling.
2. Django creates a `Case`, then dispatches Cortex analyzers via `CortexJob.run_analyzer` — each call writes an `AnalyzerReport` *and* a `CaseAnalyzerJob` ledger row atomically (`case_id ↔ cortex_job_id` mapping).
3. Cortex runs analyzers asynchronously (YARA rules, AIMailAnalyzer ML classifier, sandboxing, metadata, FileInfo) and POSTs to `/api/cortex/webhook/` (HMAC-signed, jobId-deduped) when each job finishes.
4. The webhook view looks up the case via a single indexed read on `CaseAnalyzerJob`, then enqueues `process_cortex_job(case_id, job_id)` on Celery; the task takes a per-case Redis lock, updates the ledger, and calls `finalise_case` once all pending jobs for that case are non-pending.
5. `finalise_case` aggregates scores (Safe / Inconclusive / Suspicious / Dangerous), pushes to TheHive/MISP if configured, queries ChromaDB for semantically similar past cases, notifies the reporter by SMTP, and updates dashboard KPIs.
6. Celery beat runs `update_ongoing_cases` every 300s as a webhook-delivery fallback, and `fail_stale_jobs` every 600s to auto-fail any `CaseAnalyzerJob` rows pending beyond `STALE_JOB_TIMEOUT_SECONDS` (24h default).

### Django Apps (`Suspicious/Suspicious/`)

| App | Responsibility |
|---|---|
| `api` | REST endpoints and permissions |
| `case_handler` | Case CRUD and lifecycle |
| `email_process` | Email parsing and submission |
| `cortex_job` | Cortex job orchestration (cortex4py). Defines `Analyzer`, `AnalyzerReport`, and the `CaseAnalyzerJob` junction ledger that powers the webhook lookup |
| `score_process` | Risk scoring, TheHive/MISP integration, ChromaDB queries |
| `submission_queue` | Async job queue |
| `domain_process` / `url_process` / `ip_process` / `hash_process` / `file_process` | Per-observable analysis |
| `dashboard` | KPI metrics |
| `mail_feeder` | Outbound SMTP notification templates |
| `settings` | DB-backed config (blacklists, whitelists, campaign settings) |
| `tasp` | Celery beat schedule + task wrappers (`fetch_emails`, `sync_cortex`, `update_ongoing_cases`, `process_cortex_job`, `fail_stale_jobs`, `sync_user_profiles`, `delete_old_reports`, `watcher_sync`, `materialise_dashboard_snapshots`) |
| `profiles` | User profile management |

### Frontend (`suspicious-ui/`)

React 19 + TypeScript, Vite, Material-UI (MUI v9), React Router v7, TanStack Query v5, Zustand, React Hook Form + Zod. Test stack: Vitest + jsdom + @testing-library, Playwright for end-to-end. Pages: Submit, Investigations, Campaigns, Alerts, Settings, Dashboard, Profile. API calls are proxied from Vite dev server to the Django backend.

### Email Feeder (`email-feeder/`)

Standalone Python service using Pydantic v2. Polls IMAP/IMAPS mailboxes, extracts attachments, creates cases via Django REST API, uploads artifacts to MinIO, sends acknowledgment emails via SMTP. Configured via `email-feeder/config.json`.

### AI / ML (`Analyzers/AIMailAnalyzer/`)

Sentence Transformers model (`paraphrase-multilingual-mpnet-base-v2`) for embeddings. Custom ResNetMLP binary classifier for phishing detection. Vector store is ChromaDB for similarity search against prior cases.

## Key Configuration Files

| File | Purpose |
|---|---|
| `deployment/.env` | Docker Compose environment: ports, image versions, DB and MinIO credentials, domain |
| `Suspicious/settings.json` | Main runtime config: Django secret key, DB, MinIO, Cortex, ChromaDB, TheHive, MISP, LDAP/OIDC, SMTP, branding |
| `email-feeder/config.json` | IMAP connectors, MinIO endpoint, SMTP, polling interval |
| `deployment/Makefile` | All operational tasks |

## Conventions

- Commit messages follow **Conventional Commits** (`feat:`, `fix:`, `chore:`, etc.) — see `CONTRIBUTING.md`.
- Detailed configuration options are documented in `CONFIG.md`.
- Each Django app has its own `README` describing its models and endpoints.
