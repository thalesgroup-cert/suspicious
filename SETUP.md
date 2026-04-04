# Suspicious — Deployment Guide (Docker + Make)

This guide describes how to install, initialize, and run **Suspicious** using:

* Docker Engine + Docker Compose v2
* Environment-based configuration (`.env`)
* Automated setup and validation scripts
* Makefile commands for common operations

The deployment includes automated checks for:

* directory structure
* configuration files
* TLS certificates
* permissions
* network configuration
* Cortex dependencies

# Prerequisites

## Required

| Component         | Purpose               |
| ----------------- | --------------------- |
| Docker Engine     | Runs all services     |
| Docker Compose v2 | Service orchestration |
| Git               | Repository cloning    |
| curl              | Used by setup scripts |

Installation:

* Docker: [https://docs.docker.com/get-docker](https://docs.docker.com/get-docker)
* Git: [https://git-scm.com](https://git-scm.com)

## Optional

`make` simplifies operations but is not required.

### Install `make`

**Linux**

```bash
sudo apt install make        # Debian/Ubuntu
sudo dnf install make        # Fedora/RHEL
```

**macOS**

```bash
brew install make
```

**Windows (recommended)**
Use WSL2:

```powershell
wsl --install
```

Then inside WSL:

```bash
sudo apt install make
```

All Make targets have direct script or Docker equivalents.

# Clone the Repository

```bash
git clone https://github.com/thalesgroup-cert/Suspicious.git
cd Suspicious/deployment
```

# Initialization (Required)

The initialization step prepares the environment:

* creates `.env` if missing
* validates directory structure
* copies default configuration files
* generates TLS certificates
* downloads Cortex catalogs
* checks Docker socket permissions
* configures Traefik/TLS hostname
* creates required log files and directories

Run:

```bash
make init
```

This step must be executed once before starting the stack.

# Configuration (`.env`)

If not created automatically:

```bash
cp .env.example .env
```

Edit `.env` and define:

* service versions
* ports
* database credentials
* storage paths
* domain name (Traefik / TLS)
* optional proxy settings

The `.env` file is not tracked by Git.

# Starting the Platform

## Option A — Using Make (recommended)

Start services:

```bash
make up
```

Stop services:

```bash
make down
```

Build images:

```bash
make build
```

Full deployment (production flow):

```bash
make deploy
```

This runs:

* network validation
* TLS configuration update
* queue checks
* image pull + restart
* migrations

---

## Option B — Using Docker Compose

```bash
docker compose --env-file .env up -d
```

# Access

Web interface:

👉 [http://localhost:9020](http://localhost:9020)

# Database Setup

## Run migrations

```bash
make migrate
```

## Create administrator account

```bash
make createsuperuser
```

Alternative:

```bash
docker compose exec suspicious python manage.py createsuperuser
```

# Usage

## Web Interface

Access:
👉 [http://localhost:9020](http://localhost:9020)

## Email ingestion

Send emails **as attachments** to the mailbox configured in:

```
FEEDER_PATH/config.json
```

## Manual submission

Supported inputs:

* email files (EML, MBOX)
* files
* URLs
* IP addresses
* hashes

---

# Common Operations

## Logs

All services:

```bash
make logs
```

Specific service:

```bash
make logs s=<service>
```

## Service status

```bash
make status
```

## Shell access

Web container:

```bash
make shell
```

Database shell:

```bash
make db-shell
```

## Backup

```bash
make backup-db
```

Backups are stored in:

```
./backups/
```

## Restore

```bash
make restore-db f=./backups/<file>.sql.gz
```

A 5-second delay allows abort before execution.

## Rebuild

```bash
make build
make up
```

# Stopping the Platform

```bash
make down
```

Or:

```bash
docker compose --env-file .env down
```

# Maintenance

## Restart services

```bash
make restart
```

## Pull updated images

```bash
make pull
```

## Cleanup stopped containers

```bash
make clean
```

## Full Docker cleanup (destructive)

```bash
make prune
```

Removes unused images, containers, and volumes.

# Summary

| Task         | Command                |
| ------------ | ---------------------- |
| Initialize   | `make init`            |
| Start        | `make up`              |
| Stop         | `make down`            |
| Deploy       | `make deploy`          |
| Migrate DB   | `make migrate`         |
| Create admin | `make createsuperuser` |
| Logs         | `make logs`            |
| Backup DB    | `make backup-db`       |
| Restore DB   | `make restore-db`      |
