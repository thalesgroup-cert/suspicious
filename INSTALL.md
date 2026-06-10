# Installation & Setup

Run Suspicious with Docker, from a clean clone to a working login. Every command
is copy-paste ready.

- [Prerequisites](#prerequisites)
- [Quick start (local)](#quick-start-local) — a running app in ~10 minutes
- [Configuration](#configuration) — the three config files
- [Full deployment](#full-deployment) — all services + HTTPS + UI
- [Operations](#operations) — day-to-day commands
- [Troubleshooting](#troubleshooting)
- [Uninstall](#uninstall)

---

## Prerequisites

| Tool | Minimum | Used for |
|------|---------|----------|
| Docker Engine | 24+ | runs every service |
| Docker Compose v2 | `docker compose` | orchestration |
| Git | any | clone |
| curl | any | health checks, setup scripts |
| JDK (`keytool`) | any | TLS keystore — only for the Cortex/full stack |
| Python | 3.10+ | the optional install wizard |

Check your machine:

```bash
docker version
docker compose version
git --version
```

Building images pulls from PyPI, npm, and GHCR. Behind a proxy, set `HTTP_PROXY`
and `HTTPS_PROXY` in `deployment/.env` before building.

---

## Quick start (local)

A single-machine setup for development and evaluation. It runs the database,
cache, and Django backend, and signs you in to the admin. It skips the analyzer
engine (Cortex), search (Elasticsearch), and the HTTPS proxy — add those in
[Full deployment](#full-deployment).

The example configs ship with **throwaway local credentials** that work as-is.
Change every secret before exposing this to anyone (see [Configuration](#configuration)).

```bash
# 1. Clone
git clone https://github.com/thalesgroup-cert/suspicious.git
cd suspicious

# 2. Drop in the example configs (ready to run locally)
cp docs/getting-started/examples/deployment-env.example          deployment/.env
cp docs/getting-started/examples/Suspicious-settings.example.json Suspicious/settings.json
cp docs/getting-started/examples/email-feeder-config.example.json email-feeder/config.json
cp docs/getting-started/examples/suspicious-ui-env.example        suspicious-ui/.env

# 3. Create the Docker network and build the backend image
cd deployment
docker network create suspicious_net
docker compose build suspicious

# 4. Start the data stores, then the backend
docker compose up -d db_suspicious redis_cache redis_broker
docker compose up -d --no-deps suspicious

# 5. Initialise the database and create your admin account
make migrate
make seed-config
make createsuperuser
```

Open <http://localhost:9020/admin/> and sign in.

Check the API is healthy:

```bash
curl --noproxy '*' http://localhost:9020/api/health/
# {"status": "ok", "checks": {"db": true, "redis": true, "cortex": false}, "failed": []}
```

`cortex: false` is expected here — the analyzer engine is part of the full stack.

> Behind a corporate proxy, localhost calls may be intercepted. Add `--noproxy '*'`
> to `curl`, or `export NO_PROXY=127.0.0.1,localhost`.

---

## Configuration

Three files hold all configuration. They are git-ignored — create them from the
templates (the Quick start step 2 copies ready-made examples).

| File | Template | Holds |
|------|----------|-------|
| `deployment/.env` | `deployment/.env.example` | image versions, ports, paths, DB and storage credentials |
| `Suspicious/settings.json` | `Suspicious/settings-sample.json` | Django settings, integrations, branding, SMTP |
| `email-feeder/config.json` | `email-feeder/config-sample.json` | IMAP/IMAPS mailboxes, S3, polling |

The React UI also reads `suspicious-ui/.env` (`suspicious-ui/.env.example`) for
branding shown at runtime.

### Set your own secrets

Generate a Django secret key and put it in `Suspicious/settings.json` →
`app.secret_key`:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(64))"
```

Then set, at minimum:

- `deployment/.env` → `MYSQL_PASSWORD`, `MYSQL_ROOT_PASSWORD`, `MINIO_ROOT_PASSWORD`
- `Suspicious/settings.json` → `database.password`, `branding.*`, `email.*`

### Two rules for local runs (no Vault)

1. **`Suspicious/settings.json` → `database.password` must equal
   `deployment/.env` → `MYSQL_PASSWORD`.** Without Vault, the backend reads the
   database password from `settings.json`.
2. **Set `app.debug` to `true` for plain HTTP on `localhost`.** With `debug`
   false, Django redirects to HTTPS and you must go through Traefik. Keep
   `debug` false in production.

For production, move secrets into HashiCorp Vault and set `VAULT_ADDR`. See
[deployment/VAULT.md](deployment/VAULT.md).

### Ports

| Port | Service |
|------|---------|
| 9020 | Django API (and admin) |
| 9021 | React UI (Nginx) |
| 9001 | Cortex |
| 80 / 443 | Traefik (full stack) |

---

## Full deployment

Runs all 13 services: backend, UI, Celery worker, email feeder, MariaDB,
Elasticsearch, RustFS, ChromaDB, two Valkey instances, Cortex, Vault, and
Traefik (HTTPS).

### 1. Initialise

`make init` creates config files from templates, generates TLS certificates and
the Cortex keystore, downloads the Cortex analyzer catalogs, and prepares data
directories.

```bash
cd deployment
make init
```

`make init` needs `keytool` (a JDK) and internet access for the Cortex catalogs.

### 2. Three settings the full stack requires

| Setting | File | Why |
|---------|------|-----|
| `CORTEX_PATH` set to an **absolute** path (e.g. `/opt/suspicious/cortex`) | `deployment/.env` | Cortex mounts analyzer jobs into sibling containers by host path; a relative path fails with `mount path must be absolute` |
| `app.allowed_hosts` includes your `DOMAIN_CORP` | `Suspicious/settings.json` | Traefik forwards that host; otherwise Django returns `DisallowedHost` |
| `VAULT_ADDR` left unset (dev) or pointed at a provisioned Vault (prod) | `deployment/.env` | unset falls back to `settings.json`; set requires Vault to be reachable |

### 3. Build, start, initialise

```bash
cd deployment
docker compose build suspicious suspicious_ui

docker compose up -d db_suspicious redis_cache redis_broker
docker compose run --rm --no-deps suspicious python manage.py migrate --no-input
docker compose run --rm --no-deps suspicious python manage.py seed_config
docker compose run --rm --no-deps \
  -e DJANGO_SUPERUSER_USERNAME=admin \
  -e DJANGO_SUPERUSER_PASSWORD='change-me' \
  -e DJANGO_SUPERUSER_EMAIL=admin@example.com \
  suspicious python manage.py createsuperuser --noinput

docker compose up -d
docker compose ps
```

Wait for the services to report healthy (`docker compose ps`).

### 4. Reach it over HTTPS

Traefik serves the UI on `DOMAIN_CORP` and routes `/api` to Django. Point the
domain at your host:

```bash
echo "127.0.0.1 suspicious.meridian.example" | sudo tee -a /etc/hosts
```

Open <https://suspicious.meridian.example/> and accept the self-signed
certificate. The admin is at `/admin/`.

```bash
# UI through Traefik
curl -sk --noproxy '*' -H "Host: suspicious.meridian.example" \
  -o /dev/null -w "%{http_code}\n" https://127.0.0.1/

# API through Traefik
curl -sk --noproxy '*' -H "Host: suspicious.meridian.example" \
  https://127.0.0.1/api/health/
# {"status": "ok", "checks": {"db": true, "redis": true, "cortex": true}, ...}
```

Two services may report unhealthy in a bare setup, by design:

- **email_feeder** restarts until you enable a mailbox in
  `email-feeder/config.json`. With every connector disabled it has nothing to
  poll and exits.
- **rustfs** is only used when `storage.backend` is `s3`. The quick start uses
  `local` storage.

### Email ingestion

Forward suspicious emails (as attachments) to the mailbox configured in
`email-feeder/config.json`. The feeder imports them and queues analysis.

### Feeder config authority (optional)

When enabled, the feeder fetches its S3, SMTP, and branding config from the
backend at boot instead of reading those blocks from `email-feeder/config.json`.
The backend must be reachable on first run; the feeder caches the last-good
response and tolerates a backend blip after that. With no cache and no backend
it exits. Leaving `FEEDER_API_TOKEN` blank keeps the feeder on its local
`config.json`.

```bash
# 1. Provision the feeder's scoped token (run once)
docker compose exec suspicious python manage.py create_service_token feeder

# 2. Paste the printed token into deployment/.env
#    FEEDER_API_TOKEN=<token>      (BACKEND_URL=http://suspicious:9020 is preset)

# 3. Restart the feeder so it fetches shared config from the backend
docker compose up -d --force-recreate feeder
```

---

## Operations

Run from `deployment/`.

| Command | Action |
|---------|--------|
| `make init` | Prepare configs, certificates, Cortex catalogs |
| `make up` | Create the network and start all services |
| `make down` | Stop all services (data is kept) |
| `make migrate` | Apply database migrations |
| `make seed-config` | Load runtime config into the database |
| `make createsuperuser` | Create an admin account |
| `make deploy` | Pull, migrate, seed, restart (production update) |
| `make logs` `make logs s=suspicious` | Follow logs (all, or one service) |
| `make status` | Service health |
| `make shell` | Shell into the backend container |
| `make db-shell` | MariaDB shell |
| `make backup-db` / `make restore-db f=<file>` | Backup / restore |

Every target maps to a `docker compose` command, so you can run them directly if
you prefer.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Access denied for user 'suspicious'` | `settings.json` DB password ≠ `.env` `MYSQL_PASSWORD`, or a stale database volume | Match the two; for stale data, `docker volume rm suspicious_db_suspicious_data` and restart the DB |
| `curl localhost:9020` returns `403 Server: Zscaler` | a corporate proxy intercepts localhost | `curl --noproxy '*'` or `export NO_PROXY=127.0.0.1,localhost` |
| Backend redirects to HTTPS / unreachable over `http://` | `app.debug` is `false` | set `app.debug` to `true` for local dev |
| `network suspicious_net not found` | external network not created | `docker network create suspicious_net` (or `make up`) |
| `could not read secret … from Vault at http://vault:8200` | `VAULT_ADDR` points at an unreachable Vault | leave `VAULT_ADDR` unset for local dev |
| Cortex won't start: `mount path must be absolute` | `CORTEX_PATH` is relative | set `CORTEX_PATH` to an absolute path |
| `DisallowedHost` over HTTPS | `app.allowed_hosts` missing `DOMAIN_CORP` | add your domain to `allowed_hosts` |
| `:9021/api/...` returns the page HTML, not JSON | the UI does not proxy `/api`; Traefik does | call the API through the Traefik domain |
| `docker compose build` → `uv pip install` timeout | no proxy on a proxy-only network | set `HTTP_PROXY` / `HTTPS_PROXY` in `.env` |
| `manage.py seed_config: Unknown command` | running a published image older than your code | build from source (`docker compose build suspicious`) |

---

## Uninstall

```bash
cd deployment
docker compose down            # stop services, keep data
docker compose down -v         # also delete database, storage, and search volumes
docker network rm suspicious_net
```
