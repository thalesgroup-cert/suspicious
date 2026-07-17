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
| `db_suspicious` | MariaDB 11.4 (primary read/write; opt-in replica via R6 router) |
| `redis_broker` / `redis_cache` | Valkey 9 — Celery broker + Django cache (per-case lock, webhook jobId dedup) |
| `elasticsearch` | Search and indexing |
| `rustfs` | MinIO-compatible S3 object storage (artifacts/attachments) |
| `cortex` | Analyzer execution engine (YARA, AI, sandbox); reports back via HMAC-signed webhook |
| `chromadb` | Vector DB for semantic similarity search |
| `email_feeder` | IMAP poller that auto-ingests emails (runs as non-root `feeder` UID) |
| `traefik` | Reverse proxy with TLS termination |
| `tempo` / `grafana` (optional) | OpenTelemetry trace store + dashboards; enable via `observability.opentelemetry.enabled` in `settings.json` and start the stack manually under `deployment/docker/monitoring/` (Grafana port 3000) |

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
| `connectors` | Connector framework: registry, dispatch, delivery ledger, contrib connectors for TheHive/MISP/Watcher/SMTP-notify |
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

## Full E2E Dev Deployment — `/deploy-full-e2e`

Trigger phrase for this section: "deploy full e2e", "redo the full deploy", "stand up the full stack", `/deploy-full-e2e`. Follow it step by step instead of re-deriving the process — every step below encodes a gotcha that cost real time to find the first time. This builds a *local, dev-only* full stack (all 13 services, real Cortex, no Vault/Traefik — plain HTTP on `localhost:9020`) seeded with a fictional company ("Meridian Group") and a handful of named personas, suitable for exercising the whole submit → analyze → finalize → notify pipeline end to end.

Assumes: Docker + Compose v2 working, outbound internet, a user in the `docker` group. No JDK/keytool needed on the host — worked around below. No sudo needed.

### 1. Config files (all four are git-ignored — create fresh each time)

Base them on `docs/getting-started/examples/*.example` (already a coherent "Meridian Group" example set) and layer in:
- `deployment/.env` — copy `deployment/.env.example`, fill in the `DOMAIN_CORP`/passwords from the docs example, and set `CORTEX_PATH` to an **absolute** path (e.g. `$(pwd)/cortex` under `deployment/`) — a relative path fails Cortex's mount with "mount path must be absolute".
- `Suspicious/settings.json` — copy `docs/getting-started/examples/Suspicious-settings.example.json`. Keep `app.debug: true` (plain HTTP, no Traefik). `database.password` **must equal** `.env`'s `MYSQL_PASSWORD`.
- `email-feeder/config.json` — copy `docs/getting-started/examples/email-feeder-config.example.json`.
- `suspicious-ui/.env` — copy `docs/getting-started/examples/suspicious-ui-env.example` verbatim.

### 2. `make init` and the keytool gap

Run `cd deployment && bash scripts/init.sh` (or `make init`). It downloads Cortex's `application.conf` + analyzer/responder catalogs (needs internet) and generates TLS certs — but will fail at the JVM truststore step if `keytool` (JDK) isn't on the host. Don't install a JDK — build the keystore in a throwaway container instead, then re-run init.sh so it sees the keystore already present and continues past it:
```bash
cd deployment/certificates
docker run --rm -v "$(pwd):/certs" eclipse-temurin:17-jre keytool \
  -importcert -noprompt -alias rootca -file /certs/rootcafile.pem \
  -keystore /certs/keystore.jks -storepass changeit -storetype JKS
cd .. && bash scripts/init.sh   # now completes: downloads Cortex catalogs too
```

### 3. Optional dev SMTP + LDAP

`deployment/docker-compose.dev-extras.yml` carries `greenmail` (SMTP :3025 / IMAP :3143, same image `email-feeder/docker-compose.e2e.yaml` uses for its e2e test) and `openldap` (`osixia/openldap`) as of this session — **opt-in only**, pass `-f docker-compose.dev-extras.yml` explicitly (it is deliberately not `docker-compose.override.yml`, which *is* auto-loaded, so a plain `make up`/`docker compose up` never starts these). If the file's gone, re-add it. Two non-obvious traps already worked around there:
- **SMTP AUTH is required.** `email.smtp.password` in `settings.json` can't be empty or greenmail disconnects the login. Use the same password as the IMAP user(s) in `GREENMAIL_OPTS`.
- **openldap seed data must NOT go through the image's own bootstrap-ldif volume.** That entrypoint chown/sed/rm's paths under `/container/service/slapd/assets/config/bootstrap/ldif/` in place, which fails ("Device or resource busy") against any bind mount at that exact path. Seed with `ldapadd` after the container is healthy instead:
  ```bash
  docker cp docker/openldap/custom/50-meridian.ldif openldap:/tmp/seed.ldif
  docker compose -f docker-compose.yml -f docker-compose.dev-extras.yml \
    exec openldap ldapadd -x -D "cn=admin,dc=meridian,dc=example" \
    -w "$LDAP_ADMIN_PASSWORD" -f /tmp/seed.ldif
  ```
  See `CONFIG.md` § 2.8 for why `profiles/profiles_utils/ldap.py`'s own search silently returns zero results against a plain-schema test directory like this one (hardcoded `Tpresent`/`TpreferredFirstName` attribute filter, not a standard schema).

### 4. Build and bring up

```bash
cd deployment
docker network create --driver bridge --subnet 172.20.0.0/16 \
  --gateway 172.20.0.1 --ip-range 172.20.0.0/24 suspicious_net   # or `make network`
docker compose --env-file .env build suspicious suspicious_ui feeder
docker compose --env-file .env up -d db_suspicious redis_cache redis_broker rustfs chromadb
docker compose --env-file .env -f docker-compose.yml -f docker-compose.dev-extras.yml \
  up -d greenmail openldap
```
**Gotcha:** if `Suspicious/logs/` or `email-feeder/logs/` don't exist yet, Docker auto-creates them as `root:root` on first bind mount, and the container's non-root app user then can't write its log file (`PermissionError`). Fix before running anything that writes logs:
```bash
rmdir Suspicious/logs 2>/dev/null; mkdir Suspicious/logs   # now owned by your host user = uid 1000 = container's app user
```

### 5. Migrate, seed, create users

```bash
docker compose --env-file .env run --rm --no-deps suspicious python manage.py migrate --no-input
docker compose --env-file .env run --rm --no-deps suspicious python manage.py seed_config
docker compose --env-file .env run --rm --no-deps \
  -e DJANGO_SUPERUSER_USERNAME=elena.voss@meridian.example \
  -e DJANGO_SUPERUSER_PASSWORD='MeridianDev!2026' \
  -e DJANGO_SUPERUSER_EMAIL=elena.voss@meridian.example \
  suspicious python manage.py createsuperuser --noinput
```
For the rest of the "Meridian Group" cast — spread across NORAM/LATAM/APAC/EMEA to exercise the `REGION_DICT` logic, one deliberately carrying an LDAP `businessCategory: Admin` to test the reserved-RBAC-group guard in `profiles/profiles_utils/ldap.py` — pipe this into `docker compose --env-file .env exec -T suspicious python manage.py shell -c "$(cat script.py)"`:
```python
from django.contrib.auth.models import User, Group
PERSONAS = [
    ("adaeze.okafor@meridian.example", "Adaeze", "Okafor", ["CISO"]),
    ("jordan.kim@meridian.example", "Jordan", "Kim", []),        # Marketing, US / NORAM
    ("camila.reyes@meridian.example", "Camila", "Reyes", []),    # Finance, BR / LATAM
    ("haruto.sato@meridian.example", "Haruto", "Sato", []),      # Sales, JP / APAC
    ("sam.whitfield@meridian.example", "Sam", "Whitfield", []),  # IT, GB / EMEA
]
for username, first, last, groups in PERSONAS:
    user, created = User.objects.get_or_create(
        username=username,
        defaults={"email": username, "first_name": first, "last_name": last, "is_active": True},
    )
    if created:
        user.set_password("MeridianDev!2026")
        user.save()
    for gname in groups:
        g, _ = Group.objects.get_or_create(name=gname)
        user.groups.add(g)
```

```bash
docker compose --env-file .env up -d suspicious suspicious_celery suspicious_ui feeder
```
`cortex` and `elasticsearch` come up automatically as dependencies of `suspicious`. Confirm everything: `docker compose --env-file .env ps` (all healthy) and `curl --noproxy '*' http://localhost:9020/api/health/` → `{"status": "ok", "checks": {"db": true, "redis": true, "cortex": true}, ...}`.

### 6. Edited a config file after containers are already running?

**Recreate, don't just wait.** `docker compose up -d --force-recreate --no-deps suspicious suspicious_celery` — a plain bind-mounted-file edit (most editors write-temp + rename, replacing the inode) can leave a running container looking at the old file even though it's mounted "live". If a config change doesn't seem to take effect, this is why.

### 7. Verify

```bash
docker compose --env-file .env run --rm --no-deps suspicious python manage.py test   # 525 tests as of this session
```
For a real pipeline smoke test: build a multipart email with a `message/rfc822` attachment (the phishing sample) using Python's `email` module, `smtplib.SMTP('127.0.0.1', 3025).send_message(...)` it to `suspicious@meridian.example`, wait ~10–20s for `email_feeder`'s IMAP poll, then check `Case.objects.all()` via `manage.py shell` — a case should appear and finalize automatically.

## Conventions

- Commit messages follow **Conventional Commits** (`feat:`, `fix:`, `chore:`, etc.) — see `CONTRIBUTING.md`.
- Detailed configuration options are documented in `CONFIG.md`.
- Each Django app has its own `README` describing its models and endpoints.
