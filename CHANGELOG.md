# Changelog

All notable changes to Suspicious are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Secret management moves to HashiCorp Vault, with connector secrets now editable
from the UI and Vault bring-up/unseal automated for operators.

### Added

- **Editable connector secrets from the Settings UI** — Admins/CERT can set and
  rotate `integrations.*` secrets (cortex, thehive, misp, watcher), written
  straight to Vault. New `set_secret` Vault KV v2 write primitive with a short
  TTL cache; the connector config endpoint persists secret fields to Vault and
  strips them from the DB row; UI secret fields echo a mask and leave the stored
  value unchanged when resubmitted blank.
- **Auto-seed connector secrets from settings.json into Vault on boot** — when
  Vault is configured and reachable, the app copies any
  `integrations.<connector>.<field>` secret present in `settings.json` but
  missing/empty in Vault into Vault at startup (seed-if-missing; never clobbers
  UI edits, scoped to the AppRole-writable integration paths). Lets operators
  set connector secrets in `settings.json` and have them land in Vault
  automatically.
- **Automatic Vault unseal** — `scripts/unseal-vault.sh` (idempotent) unseals the
  Vault container from a host-only `deployment/vault/unseal.keys` file; wired into
  `make up` (Vault is staged and unsealed before other services) and `make deploy`,
  plus a standalone `make unseal`.
- `make provision-vault` now writes a `suspicious-read` policy that grants scoped
  `create`/`update` on `suspicious/data/integrations/*`, so UI secret editing
  works without a manual policy edit.

### Fixed

- Vault provisioning and seeding scripts run the `vault` CLI **inside the Vault
  container** instead of requiring a host binary (previously failed with
  `vault: command not found`).
- Unseal applied only the first key (stuck at `1/3`) because `docker compose exec`
  swallowed the loop's stdin; exec stdin is now tied to `/dev/null`. The key
  parser also tolerates the verbose `vault operator init` layout and reports
  `vault status` on failure.

### Security

- Added `SECURITY.md`: Thales PSIRT responsible-disclosure contact (email + PGP
  key) and a threat model scoped to the stack, with explicit in-scope and
  out-of-scope lists.

### Documentation

- `deployment/VAULT.md` and `deployment/README.md`: copy-paste Vault bring-up
  runbook, in-container CLI usage, and the auto-unseal workflow.

## [1.4.0] - 2026-06-05

Adds the web frontend and the documentation site, plus backend changes for Celery
task processing, observability, and request resilience.

### Added

#### Frontend (new)
- **`suspicious-ui`** — React 19 + TypeScript SPA (Vite, MUI v9, React Router v7,
  TanStack Query v5, Zustand). Pages: Submit, Investigations, Campaigns, Alerts,
  Settings, Dashboard, Profile. Served via Nginx as the `suspicious-ui` service.
- Runtime env injection for the SPA — one image, per-deploy configuration.
- Pixel-exact loading skeletons (boneyard-js).
- Theming overhaul: colorblind / monochrome modes, persisted pinned navbar,
  investigation filters by result.
- Feeder `/health` badge surfaced in Settings and Home.
- Vitest + Testing Library unit tests and Playwright e2e scaffolding.

#### Documentation (new)
- MkDocs Material documentation site (`docs/`, `mkdocs.yml`) — architecture,
  components, operations, installation, contributing.
- Interactive REST API reference generated from the OpenAPI schema.
- Scoped Python code reference via mkdocstrings.
- GitHub Pages deploy workflow (`docs.yml`); docs built on PR.

#### Backend — orchestration & reliability
- **`CaseAnalyzerJob` junction ledger** — Cortex webhook resolves cases via a
  single indexed lookup; per-job `process_cortex_job` Celery task; atomic
  `case_id ↔ cortex_job_id` write in `run_analyzer`; immediate scoring on Cortex
  success; backfill + stale-rescue (`fail_stale_jobs`) tasks.
- **Celery replaces cron** — `suspicious_celery` worker + beat; `redis_broker` and
  `redis_cache` (Valkey 9); `suspicious_cron` removed; task wrappers for all 9 jobs;
  failed-task admin with requeue action.
- Mail-preview pipeline rebuilt — `eml2png` CLI replaced with imgkit, render
  offloaded to Celery with a self-healing sweeper, lazy on-miss re-render,
  regeneration management command.
- Opt-in MariaDB read replica with primary/replica router (R6).

#### Observability & health
- OpenTelemetry tracing: init module, named spans on cron/scoring entry points,
  `trace_id` injected into all JSON logs via `TraceIdFilter`.
- Grafana Tempo stack for distributed tracing.
- JSON logging + OTel SDK in the email feeder.
- `/api/health/` endpoint + container healthcheck; deepened feeder `/health`
  (IMAP + MinIO subsystem checks); standalone AIMailAnalyzer health probe.

#### Security & resilience
- SSRF IP-literal denylist on URL submission (S3).
- New security layers and metrics.
- HTTP resilience layer (`common/http_client`): `TimeoutHTTPAdapter`,
  `make_session`, retry + circuit breakers — wired into Cortex sync/fetch and
  TheHive calls.
- `settings.json` validated at boot via a pydantic schema (M8).

### Changed
- Dashboard summary/aggregate views cached in Redis (2 min TTL).
- Storage migrated from MinIO to S3-compatible (`rustfs`).
- `docker-compose.yml` image tags are now version-driven (`SUSPICIOUS_VERSION`).
- Mail handling: new email time limits and final-email template updates.
- Dependency refresh (backend + feeder).

### Performance
- Killed N+1 queries and high-cardinality FK `list_filter`s in admin.
- Deep FK prefetch across the mail chain in TheHive challenge, scoring,
  and MISP update paths (P1/P3/P4).
- `sync_user_profiles` filtered to active users with chunked iteration (P5).
- ChromaDB `n_results` parameterised (default 20).
- Index cleanup: dropped duplicate `Meta.indexes`, `fuzzy_hash` to indexed field.

### Fixed
- 52 fixes across scoring, templates, Cortex sync exception handling, watcher
  sync, dashboards, and the frontend/backend integration.

[1.4.0]: https://github.com/thalesgroup-cert/suspicious/releases/tag/v1.4.0
