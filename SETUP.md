# **Setup Guide Complete Deployment (Docker + Make + Automatic Checks)**

This guide explains how to install, initialize, and run **Suspicious** using:

* **Docker Engine & Docker Compose v2**
* **Environment-based configuration**
* **Self-contained setup scripts**
* **Optional Makefile shortcuts**

The system includes a **full checklist** to automatically validate directories, configs, certificates, permissions, and Cortex components.

# Prerequisites

Make sure the following are installed on your system.

## ✔ Required

| Component             | Purpose                          |
| --------------------- | -------------------------------- |
| **Docker Engine**     | Runs all services                |
| **Docker Compose v2** | Orchestration (`docker compose`) |
| **Git**               | Clone the repository             |
| **curl**              | Used by setup scripts            |

Installation guides:

* Docker: [https://docs.docker.com/get-docker](https://docs.docker.com/get-docker)
* Git: [https://git-scm.com](https://git-scm.com)

## ✔ Recommended

* **make** provides quality-of-life shortcuts

### Install `make`

**Linux/macOS** (if missing):

```bash
sudo apt install make        # Debian/Ubuntu
sudo dnf install make        # Fedora/RHEL
```

**Windows (recommended)**
Use **WSL2 + Ubuntu**:

```powershell
wsl --install
```

Inside WSL:

```bash
sudo apt install make
```

> 📝 *You do NOT need `make`. All actions have direct script or Docker equivalents.*

# Clone the Repository

```bash
git clone https://github.com/thalesgroup-cert/Suspicious.git
cd suspicious/deployment
```

# Initialize the Environment (Important)

The initialization phase performs:

* `.env` creation (if missing)
* Directory structure validation
* Copying sample configs when needed
* Certificate generation
* Cortex catalogs download
* Docker socket permission checks
* Traefik/TLS hostname updates
* Creation of missing log files and folders

Run:

```bash
make init
```

This MUST be executed at least once before starting the stack.

# Configure Your `.env`

If you didn’t run `make init` (which auto-creates it), create the file manually:

```bash
cp .env.example .env
```

Edit `.env` and fill in:

* service versions
* ports
* database credentials
* paths to storage directories
* domain name (for Traefik/TLS)
* optional proxy configuration

`.env` is ignored by Git for security.

# Start the Application

You have two options.

## ✔ Option A Using Make (Recommended)

### Start all services

```bash
make up
```

### Stop all services

```bash
make down
```

### Rebuild images

```bash
make build
```

### Redeploy (pull + build + safe restart)

```bash
make deploy
```

This uses:

* `check-network.sh`
* `replace-tls.sh`
* `wait-empty.sh`
* `deploy.sh`

## ✔ Option B Using Docker Compose directly

```bash
docker compose --env-file .env up -d
```

Access Suspicious:

👉 **[http://localhost:9020](http://localhost:9020)**

# Database Setup

After the containers are up, run the migrations.

## Using Make

```bash
make migrate
```

## Create a superuser

Recommended (Make):

```bash
make superuser
```

Manual:

```bash
docker compose exec web python manage.py createsuperuser
```

# Using Suspicious

## Web Interface

Open:

👉 **[http://localhost:9020](http://localhost:9020)**

## 📧 Email Submission

Send a suspicious message **as an attachment** to the mailbox configured in:

```
FEEDER_PATH/config.json
```

The system will ingest and analyze it automatically.

## 📤 Manual Submission (Web Form)

You can submit:

* Emails (EML/MBOX)
* Files
* URLs
* IP addresses
* Hashes

# Useful Commands

## 🔍 View logs

```bash
docker compose logs -f
```

## Backup the database

Using Make:

```bash
make backup
```

Direct script:

```bash
./scripts/backup-db.sh
```

## Rebuild after code changes

Using Make:

```bash
make build
```

Manual:

```bash
docker compose build --no-cache
docker compose up -d
```

# Stopping the Application

Using Make:

```bash
make down
```

Using Docker Compose:

```bash
docker compose --env-file .env down
```
