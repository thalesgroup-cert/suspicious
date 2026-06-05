# Changelog

All notable changes to Suspicious are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.0] - 2026-06-05

First release shipping the dedicated web frontend and a full documentation site,
on top of a substantial backend re-architecture around Celery, observability, and
resilience.

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
