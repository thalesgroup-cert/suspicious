# Onboarding findings & changelog

Log of every bug, inconsistency, and blocker hit while reproducing setup from
zero (the basis for [`INSTALL.md`](../../INSTALL.md)). Code fixes are committed;
config/environment issues are documented as gotchas.

## Code fixes applied (committed)

### 1. `deployment/scripts/init.sh` — wrong UI `.env` path
- **Before:** checked/copied `../../suspicious-ui/.env(.example)`.
- **After:** `../suspicious-ui/.env(.example)`.
- **Why:** `init.sh` runs from `deployment/`; the UI lives at `../suspicious-ui`,
  not `../../`. The old path pointed outside the repo, so step 2 always printed
  `ERROR: Missing both UI .env and .env.example` and never created/detected the
  UI env. Verified: corrected path resolves the existing file.

### 2. `deployment/docker-compose.overide.yml` — misnamed + unmergeable
- **Before:** filename `docker-compose.overide.yml` (typo, missing `r`) so
  Docker Compose never auto-loaded it — the dev "build from source" override was
  silently inactive and plain `docker compose up` always used the published
  image. The file also **duplicated every service**; once loaded it failed
  validation with `services.elasticsearch.security_opt items at 0 and 1 are
  equal` (the duplicated `extends` re-applied `security_opt`).
- **After:** renamed to `docker-compose.override.yml` and reduced to a **minimal
  build-only delta** (just `build:` for `suspicious`, `suspicious_ui`,
  `suspicious_celery`, `feeder`).
- **Why:** restores the intended build-from-source path; a delta (not a
  duplicate) merges cleanly. Verified: `docker compose config` passes and the
  backend build context resolves to the working tree.

Both fixes: commit `3208b96` on `feature/frontweb`.

### 3. `deployment/compose_apps.yaml` — `VAULT_ADDR` default forced Vault
- **Before:** `VAULT_ADDR: "${VAULT_ADDR:-http://vault:8200}"` on `suspicious`
  and `suspicious_celery`. A dev leaving `VAULT_ADDR` unset still got it injected
  → the backend fail-fasted at boot (`could not read secret 'app.secret_key'
  from Vault`) whenever Vault wasn't provisioned.
- **After:** `VAULT_ADDR: "${VAULT_ADDR:-}"` → unset means empty means the
  documented `settings.json` fallback. Verified: full stack boots without Vault.

### 4. `deployment/.env.example` — `CORTEX_PATH` must be absolute (documented)
- Cortex mounts analyzer job dirs into sibling containers via the Docker socket,
  so host and in-container paths must match. `CORTEX_PATH=../cortex` (relative)
  → `invalid mount path: '../cortex/jobs' mount path must be absolute`. Added a
  note + absolute example. The example settings.json `allowed_hosts` now also
  includes `DOMAIN_CORP` so the Traefik HTTPS path doesn't hit `DisallowedHost`.

Fixes 3–4 + example sync: commit `a8c6cde` on `feature/frontweb`.

### Full-stack run — verified (13 services)

Built backend + UI from source (proxy set in `.env`) and brought up the whole
stack: `db_suspicious`, `redis_cache`, `redis_broker`, `elasticsearch`,
`chromadb`, `rustfs`, `cortex`, `vault`, `traefik`, `suspicious`,
`suspicious_ui`, `suspicious_celery`, `email_feeder`. Backend health
`{db:true, redis:true, cortex:true}`. UI serves the SPA with live `window.__ENV__`
branding ("Meridian Group"). Traefik TLS (443): `/`→UI (200), `/api/health`→Django
(200), `/admin/login` →302. Note: the UI's nginx intentionally does **not**
proxy `/api` — Traefik routes it — so hit the Traefik domain, not `:9021`, for API.

## Inconsistencies documented as gotchas (no code change)

These are environment/config/design behaviors a newcomer will trip on; all are
captured in INSTALL.md §8:

- **DB password coupling.** Without Vault, `Suspicious/settings.json`
  `database.password` must equal `.env` `MYSQL_PASSWORD`, or the backend gets
  `Access denied`.
- **DEBUG vs HTTPS redirect.** `app.debug = false` forces an HTTPS redirect, so
  plain `http://localhost:9020` is unreachable without Traefik. Dev needs
  `debug = true`.
- **Stale MariaDB volume.** Credentials apply only on first init of an empty
  volume; a leftover `suspicious_db_suspicious_data` keeps old creds.
- **Cortex catalog download.** `make init` aborts (`curl: (23) ERROR on write`)
  if `cortex/Cortex-Analyzers-Public/...` is owned by another UID from a prior
  run; needs a writable tree + internet.
- **Corporate proxy on localhost.** A shell `HTTP(S)_PROXY` (e.g. Zscaler) makes
  `curl 127.0.0.1:9020` return `403`; use `--noproxy '*'`.
- **Published image lags the branch.** `ghcr.io/...suspicious:test` predates this
  branch and lacks `seed_config`; run current source via build or bind-mount.
- **`SETUP.md` is stale.** Predates `seed_config`/Vault and points "the web
  interface" at `:9020` (that is the Django API; the React UI is `:9021`).
  Superseded by INSTALL.md — a pointer was added to SETUP.md.

## Blockers — resolved

- **Backend image build** — initially failed (`uv pip install` connect timeout)
  because the build proxy was empty on a proxy-only network. **Resolved** by
  setting `HTTP_PROXY`/`HTTPS_PROXY` in `.env`; the backend image built from
  source (hvac + `seed_config` present) and the full stack ran against it.
- **Full 13-service stack** — **stood up and verified** end-to-end (see above),
  after fixing the `VAULT_ADDR` default, the relative `CORTEX_PATH`, and the
  `allowed_hosts` domain. The UI image used the published
  `ghcr.io/...suspicious-ui:test` (the SPA reads `VITE_*` at runtime, so no
  rebuild was needed to exercise branding + routing).
