# Deployment Guide

Docker Compose v2 deployment of the Suspicious stack, driven by `make` targets
that wrap the scripts in `scripts/`. Run everything from this directory.
Related guides: `docs/operations/deploy.md` (upgrades), `VAULT.md` (secrets),
`Migration_from_MinIO_to_RustFS.md`, and `CONFIG.md` at the repository root.

## Requirements

* Docker and Docker Compose v2 (`docker compose`)
* `curl`
* Outbound internet on first `make init` (Cortex catalogs)

First-time interactive setup: `make install` (runs `install.py`, writes `.env`
and `settings.json`, creates the network, optionally generates certificates and
starts the stack). `install.sh` is the curl-pipe bootstrapper that installs the
installer's dependencies and launches it.

## Quick start (non-interactive)

```bash
make init     # config files, network, certificates, secrets, Cortex catalogs
make up       # start the stack
make createsuperuser
```

`make init` (`scripts/init.sh`) checks the required binaries, creates `.env`
from `.env.example` if missing, validates the directory layout, downloads the
Cortex `application.conf` and analyzer/responder catalogs, generates TLS
certificates when missing, fills empty Redis/Elasticsearch/ChromaDB secrets
(`.env`, `.env.data`; existing values are never overwritten) and checks Docker
socket permissions.

`make up` runs `check-secrets`, `check-mounts.sh`, `check-network.sh` and
`replace-tls.sh`, starts Vault and unseals it (needs a terminal), starts
Elasticsearch and bootstraps its service accounts, then starts everything else.

## Make targets

All targets come from `Makefile`; `make help` prints the same list.

| Group | Target | What it does |
|---|---|---|
| Setup | `install` | Interactive wizard (`install.py`) |
| | `init` | Non-interactive setup (`scripts/init.sh`) |
| | `network` | Create the `NETWORK_NAME` bridge network (idempotent) |
| | `create-certs` | Generate TLS certificates (`openssl-certificates-generator.sh`) |
| | `secrets-init` | Generate missing data-service secrets (`gen-service-secrets.sh`) |
| | `install-hooks` | Set git `core.hooksPath` to `.githooks` (Conventional Commits validator) |
| Lifecycle | `up` | Start all services, no pull, no migration |
| | `down` | Stop and remove containers, volumes kept |
| | `restart` | Restart running services |
| | `redeploy [s=<svc>]` | Force-recreate containers to pick up new images; Vault is kept up and unsealed |
| | `deploy` / `upgrade` | Rolling deploy (`scripts/deploy.sh`): pull, build, migrate, restart in order |
| | `build` | Build local images and the Cortex analyzer images |
| | `pull` | Pull images without restarting |
| Django | `migrate` | `manage.py migrate` in the web container |
| | `seed-config` | Seed runtime config from `settings.json` into the DB |
| | `collectstatic` | Collect static files |
| | `createsuperuser` | Interactive Django superuser |
| Database | `backup-db` | Gzipped dump into `./backups/` (see `docs/operations/backups.md`) |
| | `restore-db f=<file>` | Restore a `.sql.gz` dump (5 s abort window) |
| | `db-replica-init`, `replica-up`, `replica-down`, `replica-status` | Optional MariaDB read replica (profile `replica`) |
| Vault | `provision-vault`, `seed-vault-secrets`, `unseal` | See "Secrets & Vault" below |
| Diagnostics | `check-secrets` | Fail if placeholder secrets remain in `.env` |
| | `db-auth-check` | Verify Redis, Elasticsearch and ChromaDB reject anonymous access |
| | `db-auth-migrate` | One-time upgrade of an existing stack to authenticated data services |
| | `network-check` | Verify each service is only on the networks it needs |
| | `check-updates` | Compare running image digests with the registry |
| | `logs [s=<svc>]`, `status`, `shell`, `db-shell` | Follow logs, `ps -a`, bash in `suspicious`, MariaDB shell |
| Cleanup | `clean`, `prune` | Remove stopped containers; prune all unused Docker resources (irreversible) |

`make deploy` first runs `check-secrets`, then `deploy.sh`, which refuses to run
until the data services enforce authentication: on an existing stack run
`make db-auth-migrate` once (about 2 minutes of maintenance window, queued
Celery tasks are discarded), then `make deploy`. Details in
`docs/operations/deploy.md`.

## Compose layout

`docker-compose.yml` (project name `suspicious`) is the entry point. It declares
volumes and networks once and pulls service definitions from the base files with
`extends:`.

| File | Role |
|---|---|
| `docker-compose.yml` | Main composition: image tags, container names, dependencies, volumes, networks |
| `compose_apps.yaml` | Base definitions for suspicious, suspicious_ui, celery, beat, cortex, docker_proxy_cortex, feeder, mail_renderer, ai_inference, vault |
| `compose_databases.yaml` | Base definitions for MariaDB (and replica), Redis, Elasticsearch, ChromaDB, RustFS |
| `compose_reverse_proxy.yaml` | Traefik |
| `docker-compose.override.yml` | Auto-loaded; only `build:` deltas so contributors run images built from their working tree |
| `docker-compose.dev-extras.yml` | Opt-in, never auto-loaded: GreenMail (SMTP 3025 / IMAP 3143), OpenLDAP, Ollama (GPU). Pass it with `-f docker-compose.yml -f docker-compose.dev-extras.yml` |
| `compose.ci.yaml` | CI overlay: stub Cortex in the `cortex` slot plus GreenMail; used by `scripts/ci/bootstrap.sh` |

`make` targets pass `--env-file .env --profile ai`.

### Profiles

| Profile | Service | Notes |
|---|---|---|
| `ai` | `ai_inference` | AIMailAnalyzer model server called by the `ai_model` connector. Enabled by every `make` target; with plain `docker compose` add `--profile ai`. Weights live in `Analyzers/AIMailAnalyzer/models/` (git-ignored) |
| `replica` | `db_suspicious_replica` | MariaDB read replica, managed by `make db-replica-init` / `replica-up` |

### Networks

`suspicious_network` is external (`NETWORK_NAME`, `NETWORK_SUBNET`,
`NETWORK_GATEWAY`, `NETWORK_IP_RANGE` in `.env`, created by `make network` or
`check-network.sh`) and is the shared integration network (reverse proxy, UI,
feeder, Vault, external peers). The others segment the stack:

| Network | Internal | Members |
|---|---|---|
| `data` | yes | MariaDB, Redis, ChromaDB proxy: Django, Celery and beat only |
| `storage` | no | RustFS: Django, Celery, the feeder and ai_inference |
| `cortex` | no | Cortex and Elasticsearch: Django and Celery |
| `renderer` | yes | `mail_renderer`: Django and Celery, no route out |
| `chroma_internal` | yes | ChromaDB and its proxy |
| `docker_cortex` | yes | Cortex and `docker_proxy_cortex` (restricted Docker socket access) |
| `reverse_network` | no | Traefik and the services it publishes |

`make network-check` verifies this membership against Docker.

## Scripts

All scripts are in `scripts/` and expect to run from `deployment/` (they
`source .env`).

| Script | Purpose |
|---|---|
| `init.sh` | Non-interactive setup behind `make init` |
| `openssl-certificates-generator.sh` | Generate the root CA, server and optional client certificates under `certificates/<env>/`; `--force` regenerates |
| `gen-service-secrets.sh` | Fill empty Redis/Elasticsearch/ChromaDB secrets with random hex, never overwriting |
| `gen-vault-tls.sh` | Generate the Vault listener certificate and CA (`vault/tls`, `vault/ca`), idempotent |
| `check-network.sh` | Create the external Docker network from `.env` if missing |
| `check-mounts.sh` | Fail before `up` when a bind-mount host path (`settings.json`, `config.json`, log dirs) is missing, since Docker would create it as a root-owned directory |
| `check-secrets.sh` | Abort when placeholder secrets remain in `.env` |
| `check-traefik-provider.sh` | Abort when `traefik.yaml` enables the Docker provider (Traefik has no Docker socket) |
| `replace-tls.sh` | Rewrite the Traefik `tls.yaml` host rule to `DOMAIN_CORP` |
| `build-analyzers.sh` | Build the local images Cortex runs the custom analyzers from |
| `deploy.sh` | Rolling deploy: pull, build, migrate, mail_renderer, web, workers, feeder, UI, then network check |
| `health-wait.sh` | Wait for a container to become healthy (used by `deploy.sh`) |
| `wait-empty.sh` | Wait until a directory in the web container is empty |
| `migrate.sh` | `manage.py migrate` in the web container |
| `create-superuser.sh` | Interactive `createsuperuser` in the web container |
| `backup-db.sh` | `mariadb-dump` into `./backups/` |
| `init-replica.sh` | Bootstrap the MariaDB read replica from the primary (dump with binlog coordinates) |
| `db-auth-check.sh` | Exit 0 only if every data service refuses anonymous access and accepts the `.env` credential |
| `db-auth-migrate.sh` | One-time upgrade to authenticated data services (`--force`, `ASSUME_YES=1`) |
| `network-check.sh` | Verify per-service network membership and reachability |
| `es-security-bootstrap.sh` | Create or refresh the Elasticsearch roles and users used by Suspicious and Cortex |
| `enable-dev-analyzers.sh` | Enable Cortex analyzers that need no API key, for dev stacks |
| `check-updates.sh` | Compare the running image digest with GHCR; exit 1 when an update exists |
| `provision-vault.sh` | Enable KV v2 and AppRole in Vault, write role and secret IDs to `.env` |
| `seed-vault-secrets.sh` | Write secrets from exported env vars into Vault KV |
| `unseal-vault.sh` | Unseal Vault from a hidden prompt; no-op if unsealed or no terminal |

---

## Secrets & Vault

### Principles

Configuration is split into three tiers — knowing which tier owns a value tells you where to set it:

| Tier | Holds | Source of truth |
|------|-------|-----------------|
| **Bootstrap** | Ports, image versions, Vault AppRole IDs, DB/MinIO bootstrap creds | `deployment/.env` |
| **Secrets** | API keys, passwords, Django secret key | HashiCorp Vault (KV v2 at `suspicious/<dotted-key>`) |
| **Runtime config** | Non-secret app settings (branding, integration URLs, …) | Database, seeded from `settings.json` |

Key rules:

* **`settings.json` is the dev/CI fallback, read-only at runtime.** Leave `VAULT_ADDR` unset and secrets are read straight from `settings.json` — no Vault needed for tests or local dev.
* **`VAULT_ADDR` set ⇒ Vault is the secret store.** Real secrets are read from Vault and overlaid onto `settings.json` paths at boot.
* **Editing connector secrets from the Settings UI requires Vault.** Admins can set/rotate `integrations.*` secrets (cortex, thehive, misp, watcher) in the UI; the write goes straight to Vault. With no Vault the UI save returns **409 secret store not configured** — set those secrets in `settings.json` instead.
* The AppRole policy written by `make provision-vault` already allows the UI to write integration secrets; everything else stays read-only.

Full secret map and details: [`VAULT.md`](VAULT.md).

### Bring up Vault (copy-paste)

Run from `deployment/`. Vault uses file storage and starts **sealed** on every boot — re-run the unseal step after each restart.

**1. Enable Vault in `.env`** (uncomment / add):

```bash
VAULT_ADDR=https://vault:8200
VAULT_PORT=8200
VAULT_PATH=./vault
```

**2. Start the stack, then initialise Vault.** Vault runs as a Compose service, so run its CLI inside the container:

```bash
make up
docker compose --env-file .env exec vault vault operator init    # FIRST BOOT ONLY — prints unseal keys + root token; record them SECURELY
export VAULT_TOKEN=<root-token>                                   # used by make provision-vault / seed-vault-secrets
```

Record the unseal keys and root token off the host (password manager, split
between operators). Vault comes up sealed on every restart; unseal it from a
terminal, typing the keys at a hidden prompt (nothing is written to disk):

```bash
make unseal    # idempotent; also run by make up / make deploy when a terminal is present
```

> Without a terminal (CI, cron) `make up` / `make deploy` leave Vault sealed and
> say so. For unattended restarts use Vault auto-unseal (cloud KMS / HSM /
> transit seal), see `VAULT.md`. A legacy `vault/unseal.keys` file (one key per
> line) is still honoured, but anyone who can read it can unseal Vault.

**3. Provision KV + AppRole** (writes `VAULT_ROLE_ID` / `VAULT_SECRET_ID` into `.env`):

```bash
make provision-vault
```

**4. Seed the secrets** (values come from your environment only — never a committed file):

```bash
export SECRET_KEY=...            # required
export DB_PASSWORD=...           # required
export CORTEX_API_KEY=...        # required
export CORTEX_WEBHOOK_SECRET=... # required
export S3_SECRET_KEY=...         # required
# optional — export only those you use:
export WATCHER_API_KEY=... THEHIVE_API_KEY=... MISP_PRIMARY_API_KEY=... \
       MISP_SECONDARY_API_KEY=... LDAP_BIND_PASSWORD=... OIDC_CLIENT_SECRET=... SMTP_PASSWORD=...
make seed-vault-secrets
```

**5. Migrate + seed runtime config, then restart:**

```bash
make deploy
```

The app now reads secrets from Vault and runtime config from the DB. Later restarts only need the unseal step (2).

> **Rotation:** update the value in Vault (`vault kv put suspicious/<dotted-key> value=...`), then restart the app containers so they re-read it at boot.

---

## Security Notes

* `.env` must never be committed; it is git-ignored and contains secrets.
* `.env.data` holds the Elasticsearch superuser password (mode 600, git-ignored); only the `elasticsearch` service and `scripts/es-security-bootstrap.sh` read it.
* Upgrading an existing stack: run `make db-auth-migrate` once (see `docs/operations/deploy.md`); `make deploy` refuses to run until the data services enforce authentication.
* Secrets can also be provided through environment variables, CI/CD secret stores or Compose overrides.
