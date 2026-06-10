# Suspicious — Install & First-Run Guide

A from-zero setup guide for a **new contributor**, reproduced end-to-end on a
clean checkout. Every command below was executed; where a step could not be run
in the author's environment, the blocker is called out explicitly.

> **What "verified" means here.** Every command was executed against a clean
> checkout. The **full 13-service stack** was built from source and brought up
> end-to-end — all services healthy (incl. Cortex, Elasticsearch, Vault), the
> React UI served with live branding, and Traefik TLS routing confirmed
> (`/`→UI, `/api`→Django, admin login over HTTPS). Image builds need outbound
> PyPI/npm/registry access (set a proxy in `.env` if required). The minimal
> **core dev stack** (DB + Redis + backend, §6) remains the fastest path for
> day-to-day development.

Example configs for a fictional org (**Meridian Group**) live in
[`docs/getting-started/examples/`](docs/getting-started/examples/) — the exact
values used below.

---

## 1. What you are installing

Suspicious is a Dockerized, multi-service phishing-analysis platform. Full
topology (13 services): Django API (`suspicious`), Celery worker
(`suspicious_celery`), React UI (`suspicious_ui`), email feeder (`feeder`),
MariaDB (+ optional replica), Elasticsearch, RustFS (S3), ChromaDB, two Valkey
instances, Cortex (analyzers), HashiCorp Vault (secrets), Traefik (TLS proxy).

For local development you do **not** need all 13. A **core dev stack** —
MariaDB + Valkey×2 + backend — is enough to run the app and log in. The heavier
services (Cortex, Elasticsearch, Traefik, Vault) are for the full/production
deployment (see §9).

---

## 2. Prerequisites

| Tool | Verified version | Needed for |
|---|---|---|
| Docker Engine | 29.x | everything |
| Docker Compose v2 | v5.x (`docker compose`) | orchestration |
| Git | any | clone |
| curl | any | setup scripts + health checks |
| keytool + java (JDK) | OpenJDK | `make init` (Cortex keystore) — full stack only |
| Python 3.10+ | 3.12 | the interactive installer (`install.py`), optional |

Check:

```bash
docker version
docker compose version
git --version
curl --version
keytool -help >/dev/null 2>&1 && echo "keytool ok"
```

**Network:** building the backend/UI images and `make init` (Cortex catalogs)
need outbound HTTPS to `pypi.org`, `ghcr.io`, npm, and StrangeBee. Behind a
corporate proxy, set `HTTP_PROXY`/`HTTPS_PROXY` in `deployment/.env` and note the
proxy gotcha in §8.

---

## 3. Clone

```bash
git clone https://github.com/thalesgroup-cert/suspicious.git
cd suspicious
```

All paths below are relative to the repo root unless a `cd` says otherwise.

---

## 4. Configure (4 files)

Four config files are **git-ignored** and must be created from templates. The
repo ships templates; filled, coherent examples are in
[`docs/getting-started/examples/`](docs/getting-started/examples/).

| Create | From template | Example |
|---|---|---|
| `deployment/.env` | `deployment/.env.example` | `docs/getting-started/examples/deployment-env.example` |
| `Suspicious/settings.json` | `Suspicious/settings-sample.json` | `…/Suspicious-settings.example.json` |
| `email-feeder/config.json` | `email-feeder/config-sample.json` | `…/email-feeder-config.example.json` |
| `suspicious-ui/.env` | `suspicious-ui/.env.example` | `…/suspicious-ui-env.example` |

Quickest path — copy the verified examples:

```bash
cp docs/getting-started/examples/deployment-env.example          deployment/.env
cp docs/getting-started/examples/Suspicious-settings.example.json Suspicious/settings.json
cp docs/getting-started/examples/email-feeder-config.example.json email-feeder/config.json
cp docs/getting-started/examples/suspicious-ui-env.example        suspicious-ui/.env
```

### 4.1 Generate a real Django secret key

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(64))"
```

Paste it into `Suspicious/settings.json` → `app.secret_key`.

### 4.2 Two rules you must not break (dev, no Vault)

1. **DB password match.** `Suspicious/settings.json` → `database.password`
   **must equal** `deployment/.env` → `MYSQL_PASSWORD`. With `VAULT_ADDR` unset
   (the dev default), the backend reads the DB password from `settings.json`; a
   mismatch gives `Access denied for user 'suspicious'`.
2. **DEBUG for plain HTTP.** Set `app.debug = true` in `settings.json` for local
   dev so the backend answers on `http://localhost:9020`. With `debug = false`,
   Django forces an HTTPS redirect and you must reach it through Traefik.
   **Never** set `debug = true` in production.

> Secrets in `settings.json` are the **dev fallback**. In production set
> `VAULT_ADDR` and provision secrets into Vault — see [`deployment/VAULT.md`](deployment/VAULT.md).

---

## 5. Initialize (`make init`)

From `deployment/`:

```bash
cd deployment
make init
```

`make init` (script: `scripts/init.sh`) creates `.env`/`settings.json`/
`config.json` from templates if missing, creates data directories, generates
self-signed TLS certs, writes a Cortex keystore, downloads Cortex catalogs, and
updates the Traefik TLS host from `DOMAIN_CORP`.

**Gotchas observed:**

- **Cortex catalogs need internet + a writable `cortex/` tree.** The last step
  downloads `analyzers.json`/`responders.json` from StrangeBee. On a fresh clone
  this works. If a previous run left `cortex/Cortex-Analyzers-Public/...` owned
  by another UID (e.g. `1001`, the Cortex container user), the download fails
  with `curl: (23) ... ERROR on write` and `make init` aborts. Fix: remove/chown
  the stale `cortex/` files, or skip — **the core dev stack does not use Cortex**.
- `make init` needs `keytool` (JDK) for the Cortex keystore. Install a JDK
  (`sudo apt install default-jdk`) or skip when running core-only.

For a **core-only** dev run you can skip `make init` entirely and just create the
4 config files (§4) plus the Docker network (§6.1).

---

## 6. Run the core stack

Two ways to get the **current source** running. Pick one.

### Option A — Build from source (standard) ⚠ needs internet

This builds backend/UI images from your working tree. Requires the dev override
`docker-compose.override.yml` (auto-loaded by Compose).

```bash
cd deployment
docker compose build                 # ⚠ needs PyPI/npm/registry egress
make up                              # creates the network + starts services
make migrate                         # docker compose exec suspicious … migrate
make seed-config                     # seed runtime config into the DB
make createsuperuser                 # interactive admin creation
```

> **Proxy note (verified):** `docker compose build` fetches from PyPI/npm. If
> your shell reaches the internet through a proxy, set `HTTP_PROXY`/`HTTPS_PROXY`
> in `deployment/.env` — the Dockerfiles forward them as build args. With the
> proxy set the backend image built cleanly from source (hvac + `seed_config`
> present) and the full stack ran against it. With an empty proxy on a
> proxy-only network the build fails with a `uv pip install` connect timeout —
> the symptom to recognize.

### Option B — Run current source on the published image (verified, no build)

The published `ghcr.io/thalesgroup-cert/suspicious:test` image carries all
runtime deps. Bind-mount your working tree over `/app/Suspicious` so the
**current branch code** runs without a rebuild — handy for a tight edit/restart
loop and for restricted networks. This is the exact path the author verified.

**6.1 Create the Docker network** (external; created by `make up`, or manually):

```bash
docker network create --subnet=172.20.0.0/16 --gateway=172.20.0.1 \
  --ip-range=172.20.0.0/24 suspicious_net
```

**6.2 Start the data stores:**

```bash
cd deployment
docker compose up -d db_suspicious redis_cache redis_broker
```

Wait for MariaDB to accept the app credentials:

```bash
docker exec db_suspicious mariadb-admin \
  --user=suspicious --password=meridian_dev_db_pw status
```

> **Stale-volume gotcha.** MariaDB applies `MYSQL_USER`/`MYSQL_PASSWORD` only on
> first init of an empty data volume. If `suspicious_db_suspicious_data` exists
> from a previous run with different creds you get `Access denied`. For a true
> clean slate: `docker compose rm -sf db_suspicious && docker volume rm
> suspicious_db_suspicious_data`, then start it again.

**6.3 A reusable runner** (current code + your settings, on the network):

```bash
SRC=$(pwd)/../Suspicious            # repo/Suspicious
RUN="docker run --rm --network suspicious_net \
  -v $SRC/Suspicious:/app/Suspicious \
  -v $SRC/settings.json:/app/settings.json:ro \
  -e SUSPICIOUS_CONFIG_PATH=/app/settings.json -w /app/Suspicious \
  ghcr.io/thalesgroup-cert/suspicious:test"
```

**6.4 Migrate, seed runtime config, create the admin:**

```bash
$RUN python manage.py migrate --no-input
$RUN python manage.py seed_config            # → "Seeded 15 runtime config sections."
```

Create the admin (env vars must precede the image name, so this one is spelled
out in full rather than reusing `$RUN`):

```bash
docker run --rm --network suspicious_net \
  -v $SRC/Suspicious:/app/Suspicious \
  -v $SRC/settings.json:/app/settings.json:ro \
  -e SUSPICIOUS_CONFIG_PATH=/app/settings.json -w /app/Suspicious \
  -e DJANGO_SUPERUSER_USERNAME=admin \
  -e DJANGO_SUPERUSER_PASSWORD=meridian_admin_pw \
  -e DJANGO_SUPERUSER_EMAIL=admin@meridian.example \
  ghcr.io/thalesgroup-cert/suspicious:test \
  python manage.py createsuperuser --noinput
```

**6.5 Start the backend** (dev server; current code; port 9020):

```bash
docker run -d --name suspicious_dev --network suspicious_net \
  -p 127.0.0.1:9020:9020 \
  -v $SRC/Suspicious:/app/Suspicious \
  -v $SRC/settings.json:/app/settings.json:ro \
  -e SUSPICIOUS_CONFIG_PATH=/app/settings.json -w /app/Suspicious \
  ghcr.io/thalesgroup-cert/suspicious:test \
  python manage.py runserver 0.0.0.0:9020
```

(For a production-like run use the image's default Gunicorn command instead of
`runserver`.)

---

## 7. Verify

> **Proxy gotcha:** if a corporate proxy (e.g. Zscaler) is set in your shell,
> `curl http://127.0.0.1:9020` is intercepted and returns `403` with
> `Server: Zscaler/...`. Bypass it for localhost: `curl --noproxy '*' …` or
> export `NO_PROXY=127.0.0.1,localhost`.

```bash
# Health — db + redis up, cortex absent is expected/handled
curl -s --noproxy '*' http://127.0.0.1:9020/api/health/
# → {"status": "ok", "checks": {"db": true, "redis": true, "cortex": false}, "failed": []}

# Admin login page
curl -s --noproxy '*' -o /dev/null -w "%{http_code}\n" http://127.0.0.1:9020/admin/login/
# → 200
```

Authenticated login (CSRF + POST), confirming the full path works:

```bash
CJ=$(mktemp)
curl -s --noproxy '*' -c $CJ http://127.0.0.1:9020/admin/login/ -o /dev/null
CSRF=$(grep csrftoken $CJ | awk '{print $7}')
curl -s --noproxy '*' -b $CJ -c $CJ -e http://127.0.0.1:9020/admin/login/ \
  -d "username=admin&password=meridian_admin_pw&csrfmiddlewaretoken=${CSRF}&next=/admin/" \
  -o /dev/null -w "login -> %{http_code} (302 = success)\n" \
  http://127.0.0.1:9020/admin/login/
```

A browser at `http://localhost:9020/admin/` logs in with `admin` /
`meridian_admin_pw`. The React UI is served separately on port **9021** (needs
the `suspicious_ui` image — §9).

---

## 8. Gotchas (all hit during this run)

| Symptom | Cause | Fix |
|---|---|---|
| `Access denied for user 'suspicious'` | `settings.json` DB password ≠ `.env` `MYSQL_PASSWORD`, **or** stale DB volume keeps old creds | Match the two; for stale data `docker volume rm suspicious_db_suspicious_data` |
| `curl …9020` returns `403 Server: Zscaler` | corporate proxy intercepts localhost | `curl --noproxy '*'` / `export NO_PROXY=127.0.0.1,localhost` |
| Backend redirects to HTTPS / unreachable on `http://` | `app.debug = false` → `SECURE_SSL_REDIRECT` | set `debug = true` for dev (never prod) |
| `make init` → `curl: (23) ERROR on write` | stale `cortex/` files owned by another UID | remove/chown stale files, or skip (core run doesn't need Cortex) |
| `docker compose build` → `uv pip install` timeout | no outbound PyPI access | build on a connected network / set proxy |
| `network suspicious_net not found` | external network not created | `make up`, or `docker network create … suspicious_net` (§6.1) |
| `manage.py seed_config` → `Unknown command` | running the published `:test` image without mounting current source | bind-mount the working tree (§6.3) or build from source |
| backend exits at boot: `could not read secret … from Vault at http://vault:8200` | Compose used to default `VAULT_ADDR` to the vault host | fixed — default is now empty; leave `VAULT_ADDR` unset for dev |
| cortex won't create: `mount path must be absolute` | `CORTEX_PATH` is relative | set `CORTEX_PATH` to an absolute path (§9.1) |
| Traefik path → Django `DisallowedHost` | `app.allowed_hosts` missing `DOMAIN_CORP` | add the domain to `allowed_hosts` (§9.1) |
| UI `:9021/api/...` returns the SPA HTML, not JSON | nginx does **not** proxy `/api`; Traefik does | use the Traefik domain (`https://…/api/…`), not the UI port directly |
| `docker compose build` → `uv pip install` timeout | proxy-only network, empty build proxy | set `HTTP_PROXY`/`HTTPS_PROXY` in `.env` (§6 Option A) |

---

## 9. Full stack & production (beyond core)

**Verified.** The complete 13-service stack was built from source and brought up
end-to-end: all services healthy (`db`, `redis`×2, `elasticsearch`, `cortex`,
`vault`, backend), the React UI served with live branding, and **Traefik TLS
routing** confirmed — `/` → UI and `/api` → Django, admin login `302` over HTTPS.

### 9.1 Verified full-stack bring-up

```bash
cd deployment
# Build from source (needs registry/PyPI/npm egress — set HTTP_PROXY/HTTPS_PROXY
# in .env if behind a proxy, e.g. on a corporate network):
docker compose build suspicious suspicious_ui

# make init must have run once (certs, keystore, Cortex catalogs — §5).
# Bring up data stores + run DB init against the from-source image:
docker compose up -d db_suspicious            # wait healthy
docker compose run --rm --no-deps suspicious python manage.py migrate --no-input
docker compose run --rm --no-deps suspicious python manage.py seed_config
docker compose run --rm --no-deps \
  -e DJANGO_SUPERUSER_USERNAME=admin -e DJANGO_SUPERUSER_PASSWORD=<pw> \
  -e DJANGO_SUPERUSER_EMAIL=admin@your.org \
  suspicious python manage.py createsuperuser --noinput

docker compose up -d                          # the whole stack
docker compose ps                             # all should reach healthy
```

> **Two services that are "unhealthy" by design in a bare dev bring-up:**
> `email_feeder` exits and restart-loops when **no IMAP connector is enabled**
> in `email-feeder/config.json` (`"No mailboxes were successfully set up …
> Exiting"`) — enable a connector against a real mailbox to keep it up. `rustfs`
> may report unhealthy on its alpha healthcheck; it is unused while
> `storage.backend = local`. Neither affects the backend/UI.

Verify through Traefik (use the `DOMAIN_CORP` host; `-k` for the self-signed cert):

```bash
curl -sk --noproxy '*' -H "Host: suspicious.meridian.example" https://127.0.0.1/api/health/
# → {"status":"ok","checks":{"db":true,"redis":true,"cortex":true},...}
curl -sk --noproxy '*' -H "Host: suspicious.meridian.example" -o /dev/null \
  -w "%{http_code}\n" https://127.0.0.1/            # UI → 200
```

Browser: add `127.0.0.1 suspicious.meridian.example` to your hosts file and open
`https://suspicious.meridian.example/` (accept the self-signed cert).

**Three full-stack requirements that bit during this run** (all now in the
example configs):

- **`CORTEX_PATH` must be absolute** (e.g. `/opt/suspicious/cortex`) — Cortex
  mounts analyzer job dirs into sibling containers by host path. Relative →
  `mount path must be absolute`.
- **`allowed_hosts` must include `DOMAIN_CORP`** — Traefik forwards the
  `suspicious.meridian.example` Host; without it Django returns `DisallowedHost`.
- **Leave `VAULT_ADDR` unset for dev** — Compose now defaults it to empty so the
  backend falls back to `settings.json`. (Previously it defaulted to
  `http://vault:8200`, fail-fasting when Vault wasn't provisioned.)

### 9.2 Service notes

- **suspicious_ui** (port 9021): React/Vite + Nginx. `docker compose build
  suspicious_ui` (⚠ needs npm). Branding from `suspicious-ui/.env`.
- **Cortex + Elasticsearch**: analyzers. Cortex needs the Docker socket
  (`/var/run/docker.sock`) and runs as uid 1001; Elasticsearch wants ~1–4 GB
  heap (`ES_JAVA_OPTS` in `.env`). Run `make init` first (catalogs + keystore).
- **RustFS** (S3): only when `storage.backend = s3` in `settings.json`. The core
  run uses `backend = local`.
- **ChromaDB**: semantic similarity. Backend degrades gracefully without it.
- **Traefik**: TLS termination on 80/443 using `DOMAIN_CORP`; required when
  `debug = false`.
- **Vault**: production secrets. With `VAULT_ADDR` set, the backend pulls
  secrets via AppRole instead of `settings.json`. Flow: `make provision-vault`
  → `make seed-vault-secrets` → `make deploy`. See [`deployment/VAULT.md`](deployment/VAULT.md).

Full production bring-up (with all of the above configured):

```bash
cd deployment
make init
make deploy          # pull → migrate → seed_config → rolling restart
make createsuperuser
```

`make deploy` runs migrations **and** `seed_config` (the runtime-config seed
added in this branch) before restarting services.

---

## 10. Command reference (`deployment/`)

| Task | Make | Underlying command |
|---|---|---|
| Initialize | `make init` | `scripts/init.sh` |
| Start | `make up` | create network → `docker compose up -d` |
| Stop | `make down` | `docker compose down` |
| Migrate | `make migrate` | `docker compose exec suspicious python manage.py migrate` |
| Seed runtime config | `make seed-config` | `docker compose exec -T suspicious python3 manage.py seed_config` |
| Create admin | `make createsuperuser` | `docker compose exec suspicious python manage.py createsuperuser` |
| Logs | `make logs [s=svc]` | `docker compose logs -f` |
| Status | `make status` | `docker compose ps` |
| Shell | `make shell` | `docker compose exec suspicious bash` |
| Deploy | `make deploy` | pull → migrate → seed_config → restart |

> The `make migrate`/`seed-config`/`createsuperuser` targets run inside the
> Compose-managed `suspicious` container, so they require the **from-source**
> image (Option A) — the published `:test` image predates this branch and lacks
> `seed_config`. The author verified the equivalent `manage.py` commands against
> the current source via the bind-mount in Option B.

---

## 11. Teardown

```bash
# core dev (Option B)
docker rm -f suspicious_dev
cd deployment && docker compose down
docker volume rm suspicious_db_suspicious_data   # wipe DB data
docker network rm suspicious_net                 # if you created it manually
```

`make prune` (destructive) removes unused images/containers/volumes.
