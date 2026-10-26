# Changelog

All notable changes to Suspicious are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

A connector framework rewrite (pluggable contrib connectors, lifecycle events, a
delivery ledger), a rebuilt scoring engine, a Cortex job/webhook re-architecture
around a `CaseAnalyzerJob` ledger, a redesigned settings UI, and secret
management moving to HashiCorp Vault.

### Added

#### Connectors
- **Contrib connector architecture** — TheHive, MISP, Watcher, and SMTP
  notification migrated off bespoke integration code onto a common `Connector`
  base with a registry, `ConnectorState`/`ConnectorDelivery` models, and
  Celery fan-out dispatch. `case_created`/`case_finalised` lifecycle events
  replace direct calls into each integration.
- **`ChromaDBConnector`** registered as a builtin — nightly cleanup of expired
  similarity-collection items, wrapped in a background-thread timeout so a
  hung ChromaDB server can't block a Celery worker until the global task
  timeout fires; retires the old ad-hoc cleanup task and beat entry.
- Connector management API and UI: list/toggle/configure/test/deliveries
  endpoints, a category + computed status field, and third-party packaging
  hooks with authoring docs for external connectors.
- Case comments sync to TheHive threads, with challenge reason and proposed
  verdict surfaced in the alert.

#### Scoring
- **Rewritten scoring engine** — a pure `score_case` function over typed
  `Signal`/`CaseVerdict` inputs, with `apply_verdict` as the sole writer of a
  case's scoring fields and a read-only `backtest_scoring` drift command for
  validating engine changes against historical cases.
- **Per-analyzer parser registry** (`AnalyzerParserRegistry`, resolved by name
  or Cortex analyzer id) — dedicated parsers for CirclHashlookup, MISP,
  Urlscan, VirusTotal, Zscaler, the default taxonomy shape, and the AI mail
  classifier (ported onto the same `AnalyzerParser` base, confidence 0-100).

#### Cortex job orchestration
- **`CaseAnalyzerJob` ledger** — an indexed junction table mapping
  `case_id ↔ cortex_job_id`, backfilled from existing `AnalyzerReport` rows.
  The webhook now does a single indexed lookup instead of a broader query, and
  each report is scored immediately on a Cortex success rather than waiting
  for the next sweep.
- Per-job `process_cortex_job` Celery task with a per-case Redis lock; Cortex
  dispatch deferred until after case creation so a slow/failed dispatch can't
  block case creation itself; the cron path slimmed to a fallback role plus a
  stale-job rescue task anchored to `CaseAnalyzerJob.created_at`.

#### Frontend
- Connectors panel rebuilt as a two-pane master/detail layout with a
  recent-deliveries history view; Avatar panel rebuilt as a two-column "Split
  Studio" layout.
- New shared components: collapsible `EnumField` thumbnail grid, `ColorField`
  swatch + hex picker, `MailPreview`, `ResultChip`, `StatusChip`, `SoftCard`.
- Settings scoping (`RuntimeConfig`, `get_scope_config`, scope-aware
  `seed_config`) and a `create_service_token` command for scoped
  config-authority access, feeding the feeder's own config authority.

#### Secrets (Vault)
- **Editable connector secrets from the Settings UI** — Admins/CERT can set and
  rotate `integrations.*` secrets (cortex, thehive, misp, watcher), written
  straight to Vault. New `set_secret` Vault KV v2 write primitive with a short
  TTL cache; the connector config endpoint persists secret fields to Vault and
  strips them from the DB row; UI secret fields echo a mask and leave the stored
  value unchanged when resubmitted blank.
- **Vault → settings.json read fallback for section secrets** — `get_section`
  now resolves each secret leaf from Vault first and falls back to the
  `settings.json` value when Vault is unset or has no value for the key (was
  previously empty when Vault was configured but missing the key). Boot-critical
  secrets read via `get_secret(fail_fast=True)` are unaffected.
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

#### Automation / SOAR API
- **`external_ref` on every submit endpoint** — the caller's own reference (for
  example a SOAR incident id). Re-submitting the same reference returns the
  original case (HTTP 200, `reused: true`) before any file is stored or
  analyzer queued, so a replayed playbook step cannot create duplicate cases.
  Scoped to the reporter; stored on `Case.external_ref` (migration
  `case_handler.0032`); echoed in the submission list/detail rows and the
  ticket payload; filterable with `?external_ref=` on `/api/submissions/`.
- **`GET /api/submissions/<id>/verdict/`** — a compact poll target for
  automations. `done` is true once the verdict is final; `result` stays null
  until then. Open to the reporting account, so an automation no longer needs
  the investigator role just to wait for a result.
- **`GET /api/lookup/?type=&value=`** — the verdict already on file for a URL,
  IP, domain or hash, without creating a case (investigators only). Powers
  reputation-style enrichment.
- **Cortex XSOAR pack** (`integrations/xsoar/Packs/Suspicious`) — submit
  commands with built-in polling, `suspicious-get-verdict/ticket/report`,
  `suspicious-challenge`, and the `url`/`ip`/`domain`/`file` reputation
  commands returning DBot scores.
- **`xsoar` connector** — opens one Cortex XSOAR incident per finalised case at
  or above `min_verdict` (verdict, rationale, per-observable verdicts, link to
  the case), so cases that start in Suspicious reach the SOC. Skips cases an
  XSOAR playbook submitted; records the incident per case in the new generic
  `ConnectorLink` table so a replayed event opens nothing.

#### CI/CD
- CI consolidated onto a single matrix workflow (ruff, Django suite, feeder
  pytest, UI lint/typecheck/vitest-browser/build, docker build matrix) and a
  release workflow that builds, pushes, generates an SBOM, and attests build
  provenance. A full-stack `e2e-deploy` smoke gate boots the real stack
  (Cortex stubbed) and drives one email through feeder → S3 → backend → case →
  ledger → finalise → preview, asserting every hop.
- New `security.yml`: Trivy filesystem scan, gitleaks, and `pip-audit`/
  `pnpm audit` across all four Python/JS dependency sets, gating any PR into
  `main`.
- MkDocs documentation site deploy workflow.

#### Storage
- **Google Cloud Storage provider**: set `storage.provider` to `gcs` and
  configure `storage.gcs` (ADC, service account JSON or emulator credentials,
  V4 signed URLs with key or keyless signing). See `CONFIG.md`.

### Changed

- **Object storage moves from `minio-py` to `boto3`** behind a provider-agnostic
  `ObjectStore` interface (`common/storage/`). No config change is needed:
  `storage.provider` (or `STORAGE_PROVIDER`) is optional and defaults to `s3`.
  The legacy bucket-per-email tag scanner now needs a provider with free-form
  bucket tags. S3 client timeouts are now 5 s connect and 15 s read with 2
  retries (`minio-py` used 300 s), and botocore honours `HTTP_PROXY`,
  `HTTPS_PROXY` and `NO_PROXY` (`minio-py` did not), so an external
  `storage.s3.endpoint` must be listed in `NO_PROXY`.
- **Allow-lists are a weighted vote in `score_case`**: a strict majority of
  Safe plus allow-listed analyzer weight now yields Safe (rule
  `allow-list-majority`), with dissenting analyzers named in the rationale.
- Old `docker-image-latest`/`docker-image-tags`/`docker-image-test` workflows
  retired in favor of the CI/release matrix above.
- `docker-compose.override.yml`'s dev-only `greenmail`/`openldap` stubs moved
  to an opt-in `docker-compose.dev-extras.yml` — a plain `make up` no longer
  starts them; pass `-f docker-compose.dev-extras.yml` explicitly.
- Per-app log files with corrected logger nesting and a root-logger safety
  net; web-submission case creation no longer logs into the fetch-mail log.
- Out-of-scope submission ids now return 404 instead of 403, including another
  user's id on the challenge endpoint.
- A CISO acting on their own submission gets the reporter view (no analyst
  ticket, no internal comments).
- Mail previews are rendered from sanitised HTML: remote styles, links and
  images and some stylesheets are dropped, and very large mails are truncated.

### Fixed
- **Challenge flow**: the emailed challenge link opens a form instead of
  changing the case when fetched, so mail scanners and link previews can no
  longer challenge a case or spend the token. The form and the in-app dialog
  both require a proposed verdict and a reason (10 characters or more). The
  token, the case mark, the proposal and a timeline comment are written in one
  transaction; a second challenge of the same case is refused, and a failing
  TheHive alert no longer turns a recorded challenge into an error page.
- **TheHive challenge alerts** now carry what campaign alerts carry: extracted
  observables, the original mail and its attachments as file observables, an
  indicators section, the case link, the verdict rationale and severity from the
  verdict (artifacts were always empty before). Files are sent either as
  observables (analysed by TheHive) or as alert attachments (evidence, the
  rendered mail), never both, also for campaign alerts. Hash observables are
  tagged with their file name and existing ones get missing tags on the next
  sync. Alert descriptions defang URLs, domains, IPs and addresses.
- **Allow-lists no longer over-reach**: allow-listed IPs no longer launch
  Cortex jobs (email and web submit); an allow-list entry no longer silences a
  deny-listed, Watcher-monitored or campaign domain; MISP no longer receives
  campaign-domain indicators or allow-listed URLs, IPs and hashes (domains and
  URL hosts match exactly).

- **Cortex analyzer launch dispatches asynchronously** from the submit path,
  so a slow Cortex doesn't hold up the request that creates the case.
- **Cortex 5xx responses now retry correctly**, and `category_ai` is bounded
  to its column width instead of erroring on overflow.
- **SMTP send now authenticates** — Microsoft 365 was rejecting outbound mail
  as anonymous relay.
- **Attachment filenames truncated by bytes instead of characters**, which
  was silently breaking object-storage fetch for multi-byte filenames.
- AI mail analyzer confidence was being scaled twice (once in the parser, once
  in scoring), and MISP/Urlscan/VirusTotal parsers now guard against
  non-list/non-dict scalar payloads instead of raising.
- `thehive_alert_id` now persists after a challenge alert is created; TheHive
  attachment upload fixed (wrong endpoint, fragile `.eml` fetch); thread
  comments post as `always_append` instead of a lossy dedup-merge.
- **Install wizard generated an unused secret key** — `install.py` auto-generated
  a Django secret key into `.env` (which nothing reads) while leaving
  `settings.json` `app.secret_key` at the committed sample value, so non-Vault
  installs ran on a publicly known key. The generated key is now written to
  `app.secret_key`.
- Vault provisioning and seeding scripts run the `vault` CLI **inside the Vault
  container** instead of requiring a host binary (previously failed with
  `vault: command not found`).
- Unseal applied only the first key (stuck at `1/3`) because `docker compose exec`
  swallowed the loop's stdin; exec stdin is now tied to `/dev/null`. The key
  parser also tolerates the verbose `vault operator init` layout and reports
  `vault status` on failure.

### Security

- **No Docker socket in Traefik or Cortex.** Both reach the daemon through a
  socket proxy on a private network: Traefik through a read-only proxy (list
  containers and events, no writes), Cortex through a proxy that allows only
  what its job runner calls. If your `traefik.yaml` defines the Docker
  provider, set its endpoint to `tcp://docker_proxy_traefik:2375` (`make deploy`
  checks). The Cortex proxy narrows the Docker API surface but cannot filter
  request bodies; see `docs/operations/deploy.md`. The Django, Celery, beat and
  feeder containers drop all Linux capabilities and set `no-new-privileges`; the
  UI and Cortex keep only the four they need to switch user.
- **Network segmentation.** The flat stack network is split: MariaDB, Redis and
  the Chroma proxy sit on an internal `data` network, RustFS on `storage`, and
  Cortex with Elasticsearch on `cortex`, each reachable only by the services
  that need it (the UI, reverse proxy, Vault and feeder cannot reach a
  database). `make network-check` verifies the layout and `make deploy` runs
  it and moves MariaDB and RustFS onto their networks on upgrade (one short
  restart). See `docs/operations/deploy.md`.
- **Data services require authentication.** Redis (broker and cache) needs a
  password, Elasticsearch has security enabled with separate service accounts
  for the application and Cortex, and ChromaDB sits behind a token-checking
  proxy on an isolated network. `make init` generates the secrets;
  `make db-auth-migrate` upgrades an existing deployment (a short maintenance
  window, see the deployment docs). The Helm chart does not yet configure
  service authentication.

- Added `SECURITY.md`: Thales PSIRT responsible-disclosure contact (email + PGP
  key) and a threat model scoped to the stack, with explicit in-scope and
  out-of-scope lists.
- First CodeQL run against this body of work triaged: hardened attachment/
  submission path handling (`os.path.basename` at both taint roots), stopped
  logging a Vault write failure's exception string (could echo back the
  secret value on certain HTTP client errors), and `chmod 0600` on the
  installer-generated `.env`. One accepted, documented exception: a
  pre-auth ChromaDB RCE with no upstream fix yet, verified unreachable since
  this app only uses ChromaDB as an `HttpClient`.
- Dependency bumps closing known CVEs: `pillow`, `django`, `jinja2`, `nltk`,
  the `opentelemetry` stack (needed to unblock a `protobuf` fix), and on the
  UI side `vite`, `undici`, `form-data`.
- Mail preview rendering is hardened: HTML is sanitised with an allow-list
  (`nh3`) and rendered without network access.
- CISO scope now applies to submission endpoints (list, detail, verdict, ticket,
  comments, report, mail preview, screenshot, URL analysis); a CISO without a
  profile sees no cases instead of all of them.
- Redis (broker and cache), Elasticsearch and ChromaDB now require authentication
  on the internal network: per-service secrets are generated by `make init`, and
  existing deployments upgrade once with `make db-auth-migrate` (`make deploy`
  refuses to run until then). ChromaDB sits behind a token-checking proxy.
  Known limitation: the Helm chart is not yet configured for service
  authentication and still deploys the unauthenticated data services.
- Submission bucket names are normalised to valid S3 names (uppercase,
  underscores, dots, non-ASCII and long usernames no longer break uploads).

### Documentation

- `deployment/VAULT.md` and `deployment/README.md`: copy-paste Vault bring-up
  runbook, in-container CLI usage, and the auto-unseal workflow.
- Third-party connector authoring docs for the new contrib architecture.

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
