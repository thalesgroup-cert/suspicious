# 🚀 **Setup Guide — Modern Deployment (Docker + Make)**

This document explains how to install and run **Suspicious** locally using **Docker**, **Docker Compose v2**, and optional **Makefile shortcuts**.

---

## 1️⃣ Prerequisites

Make sure the following are installed:

### ✔ Required

* **Docker** – [https://docs.docker.com/get-docker](https://docs.docker.com/get-docker)
* **Docker Compose v2** (included in Docker Desktop / Docker Engine)
* **Git** – [https://git-scm.com](https://git-scm.com)

### ✔ Optional but recommended

* **make** (quality-of-life improvement)

#### macOS / Linux

Usually preinstalled. If missing:

```bash
# Ubuntu/Debian
sudo apt install make

# Fedora/RHEL
sudo dnf install make
```

#### Windows (Recommended)

Use **WSL2** + Ubuntu:

```powershell
wsl --install
```

Inside WSL:

```bash
sudo apt install make
```

> 📝 *You do NOT need `make`. All Makefile commands have script equivalents.*

---

## 2️⃣ Clone the Repository

```bash
git clone https://github.com/thalesgroup-cert/Suspicious.git
cd suspicious
```

---

## 3️⃣ Environment Configuration

### 1. Create your `.env` file

```bash
cp .env.example .env
```

### 2. Edit `.env`

Fill in required values:

* application versions
* application ports
* database credentials
* container names
* network config
* application paths
* optional proxies

`.env` is ignored by Git for safety.

---

## 4️⃣ Start the Application

You can start Suspicious in two ways:

---

## ✔ Option A — Using Make (Recommended)

Start all services:

```bash
make up
```

Stop everything:

```bash
make down
```

Rebuild:

```bash
make build
```

Deploy fully (pull + build + restart):

```bash
make deploy
```

---

## ✔ Option B — Using Docker Compose directly

```bash
docker compose up -d
```

The application will now be available at:

👉 **[http://localhost:9020](http://localhost:9020)**

---

## 5️⃣ Post-Installation (Database Setup)

Run these for suspicious database setup.

### ✔ Using Make

```bash
make migrate
```

Create an admin user:

```bash
docker compose exec web python manage.py createsuperuser
```

### ✔ Or manually

```bash
docker compose exec web python manage.py migrate
docker compose exec web python manage.py createsuperuser
```

---

## 6️⃣ Usage

### 🌍 **Web Interface**

Access the application:

👉 [http://localhost:9020](http://localhost:9020)

### 📧 Mail Submission

Send a suspicious email **as an attachment** to the configured mailbox.
The system will analyze it automatically.

### 📤 Web Form Submission

Use **Submit an Item** to upload:

* Emails
* Files
* URLs
* IPs
* Hashes

---

## 7️⃣ Useful Commands

### 🔍 Logs

```bash
docker compose logs -f
```

### 💽 Database Backup

```bash
make backup
```

or:

```bash
./scripts/backup-db.sh
```

### 🛠 Rebuild After Code Changes

```bash
make build
```

or:

```bash
docker compose build --no-cache
docker compose up -d
```

---

## 8️⃣ Stopping the Application

Using Make:

```bash
make down
```

Using Compose:

```bash
docker compose down
```
