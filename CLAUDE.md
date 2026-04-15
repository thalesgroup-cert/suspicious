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
make monitor-up         # Enable Prometheus + Grafana (port 3000)
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
| `suspicious_cron` | Django cron worker (background jobs) |
| `suspicious_ui` | React/Vite frontend (Nginx, port 9021) |
| `db_suspicious` | MariaDB 12 |
| `elasticsearch` | Search and indexing |
| `rustfs` | MinIO-compatible S3 object storage (artifacts/attachments) |
| `cortex` | Analyzer execution engine (YARA, AI, sandbox) |
| `chromadb` | Vector DB for semantic similarity search |
| `email_feeder` | IMAP poller that auto-ingests emails |
| `traefik` | Reverse proxy with TLS termination |

### Request / Analysis Flow

1. User submits email/file/URL/IP/hash via web UI, API, or the email feeder's IMAP polling.
2. Django creates a `Case` and dispatches `CortexJob` tasks to the Cortex analyzer engine.
3. Cortex runs analyzers: YARA rules, AIMailAnalyzer ML classifier, sandboxing, metadata checks.
4. Results are scored (Safe / Inconclusive / Suspicious / Dangerous) and stored; ChromaDB is queried for semantically similar past cases.
5. User is notified by email; dashboard KPIs are updated.

### Django Apps (`Suspicious/Suspicious/`)

| App | Responsibility |
|---|---|
| `api` | REST endpoints and permissions |
| `case_handler` | Case CRUD and lifecycle |
| `email_process` | Email parsing and submission |
| `cortex_job` | Cortex job orchestration (cortex4py) |
| `score_process` | Risk scoring, TheHive/MISP integration, ChromaDB queries |
| `submission_queue` | Async job queue |
| `domain_process` / `url_process` / `ip_process` / `hash_process` / `file_process` | Per-observable analysis |
| `dashboard` | KPI metrics |
| `mail_feeder` | Outbound SMTP notification templates |
| `settings` | DB-backed config (blacklists, whitelists, campaign settings) |
| `tasp` | Cron job scheduling |
| `profiles` | User profile management |

### Frontend (`suspicious-ui/`)

React 19 + TypeScript, Vite, Material-UI (MUI v7), React Router v7, TanStack Query v5, Zustand, React Hook Form + Zod. Pages: Submit, Investigations, Campaigns, Alerts, Settings, Dashboard, Profile. API calls are proxied from Vite dev server to the Django backend.

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
