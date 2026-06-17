# Modern Deployment Guide

This project provides a **modular, automated, Docker-based deployment system** designed for reliability, maintainability, and ease of use.
It relies on:

* **Docker Compose v2**
* **Environment configuration via `.env`**
* **Self-contained helper scripts** (`scripts/`)
* **Optional Makefile shortcuts** for convenience
* A comprehensive **checklist** that prepares all required files, directories, and certificates

---

## Requirements

Before running any commands, ensure you have:

* **Docker**
* **Docker Compose v2 (`docker compose` subcommand)**
* **curl**

The `scripts/init.sh` and `scripts/check-network.sh` utilities will verify and prepare the environment automatically.

---

## Initialization

Run the full initialization script:

```bash
make init
```

This performs:

* Creation of the `.env` file (or uses yours if present)
* Directory structure validation
* Download/creation of config files
* Certificate generation (if missing)
* Cortex catalog download
* Check of Docker socket permissions
  …and other required system checks.

This step ensures the project is ready to run.

---

## Starting the Stack

### Start all services

```bash
make up
```

or manually:

```bash
docker compose --env-file .env up -d
```

### Stop all services

```bash
make down
```

---

## Deployment Workflow

To pull new images, rebuild if needed, and restart services safely:

```bash
make deploy
```

This command runs:

* Network checks
* TLS/hostname replacement
* Safety check for empty workload queues
* Deployment script execution

---

## 🛠 Development & Maintenance Commands

### Build images

```bash
make build
```

### Pull latest images

```bash
make pull
```

### Run database migrations

```bash
make migrate
```

### Create a superuser

```bash
make superuser
```

### Backup the database

```bash
make backup
```

### Regenerate certificates

```bash
make create-certs
```

---

## Project Structure

```
.
├── docker-compose.yml           # Main orchestration file
├── .env.example                 # Example configuration (safe to commit)
├── .env                         # Real configuration (never commit)
├── scripts/                     # Modular shell scripts
│   ├── init.sh                  # Main initializer (system checks + setup)
│   ├── check-network.sh
│   ├── wait-empty.sh
│   ├── deploy.sh
│   ├── migrate.sh
│   ├── backup-db.sh
│   ├── create-superuser.sh
│   └── openssl-certificates-generator.sh
└── Makefile                     # User-friendly command shortcuts
```

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
VAULT_ADDR=http://vault:8200
VAULT_PORT=8200
VAULT_PATH=./vault
```

**2. Start the stack, then initialise + unseal Vault.** Vault runs as a Compose service, so run its CLI inside the container:

```bash
make up
docker compose --env-file .env exec vault vault operator init    # FIRST BOOT ONLY — record unseal keys + root token SECURELY
docker compose --env-file .env exec vault vault operator unseal   # repeat with the threshold number of keys
export VAULT_TOKEN=<root-token>                                   # used by make provision-vault / seed-vault-secrets
```

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

* `.env` **must never be committed** — it contains secrets.
* `.env` is already included in `.gitignore`.
* Secrets can also be provided through:

  * environment variables
  * CI/CD secret stores
  * Docker Compose overrides

---

## Summary

| Action                | Command             |
| --------------------- | ------------------- |
| Initialize everything | `make init`         |
| Start services        | `make up`           |
| Stop services         | `make down`         |
| Deploy updates        | `make deploy`       |
| Provision Vault       | `make provision-vault` |
| Seed Vault secrets    | `make seed-vault-secrets` |
| Run migrations        | `make migrate`      |
| Backup database       | `make backup`       |
| Create superuser      | `make superuser`    |
| Generate certificates | `make create-certs` |
