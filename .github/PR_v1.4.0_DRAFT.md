# [V1.4.0] Web frontend, documentation site, and backend re-architecture

> Draft PR body — `test` → `main` on `thalesgroup-cert/suspicious`. Not yet opened.

## Summary

Releases **v1.4.0** by merging the `test` integration branch into `main`. Adds the
web frontend (`suspicious-ui`) and the MkDocs documentation site, plus backend changes
for Celery task processing, observability, and request resilience.

- **284** non-merge commits since v1.3.4 — 41 feat, 52 fix, 8 perf, 24 docs, 11 ci.
- **2766** files changed (`+61,296 / −529,873`) — frontend addition plus large cleanup.
- New top-level paths: `suspicious-ui/`, `docs/`, `mkdocs.yml`, `CLAUDE.md`,
  `.githooks/`, `ruff.toml`.

## Highlights

### Frontend (new)
React 19 + TypeScript SPA (Vite, MUI v9, Router v7, TanStack Query, Zustand) served
via Nginx. Pages: Submit, Investigations, Campaigns, Alerts, Settings, Dashboard,
Profile. Runtime env injection (one image, per-deploy config), themeing overhaul
(colorblind/monochrome), loading skeletons, feeder health badge. Vitest + Playwright.

### Documentation (new)
MkDocs Material site — architecture / components / operations / install / contributing,
interactive OpenAPI REST reference, mkdocstrings Python reference, GitHub Pages deploy.

### Backend
- `CaseAnalyzerJob` ledger → indexed webhook lookup + per-job `process_cortex_job`.
- Celery replaces cron: `suspicious_celery` + `redis_broker`/`redis_cache`,
  `suspicious_cron` removed, stale-job rescue.
- OpenTelemetry tracing + Grafana Tempo; `trace_id` in JSON logs.
- `/api/health/` + deepened feeder health probes.
- SSRF denylist, HTTP timeout/retry/circuit-breaker layer, pydantic-validated settings.
- Perf: N+1 elimination, deep FK prefetch (P1/P3/P4), Redis-cached dashboards,
  index cleanup, MinIO→S3 (`rustfs`), opt-in MariaDB read replica.

See `CHANGELOG.md` for the full breakdown.

## CI / release status
- Latest `test` run (#153, 2026-06-03): **CI ✅ / Release ✅** — `test`-tagged images
  already built and pushed to GHCR with SBOM + provenance.

## Release checklist (post-merge)
- [ ] Merge this PR into `main`.
- [ ] Tag `v1.4.0` → fires `release.yml` (semver + `latest` images, SBOM, provenance).
- [ ] **Enable GitHub Pages (source: GitHub Actions) on the repo** — `docs.yml` deploys
      Pages on `main` for the first time; deploy fails if Pages is not enabled.
- [ ] Publish GitHub Release `v1.4.0` using the `CHANGELOG.md` 1.4.0 section.
- [ ] Bump `suspicious-ui/package.json` version (currently `0.2.0`) for consistency.

## Breaking changes
None expected for end users. Operational note: deployment topology changed —
`suspicious_cron` is gone; `suspicious_celery`, `redis_broker`, `redis_cache` are
required. Review `deployment/.env` / compose before upgrading.
