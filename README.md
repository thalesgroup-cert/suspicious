# Suspicious

**Suspicious** is a modern phishing-analysis platform designed to help organizations automatically inspect, classify, and report suspicious emails, files, URLs, IPs, and hashes.
It helps reduce analyst workload, enables fast triage, and provides end-users with clear security feedback.

Phishing attacks continue to grow in sophistication, leveraging social engineering, malware, and credential harvesting. **Suspicious** provides a structured, automated, and scalable defense by combining:

- ✅ A fast, intuitive web interface
- ✅ Deep analysis through **Cortex analyzers**, YARA, and sandboxing
- ✅ Automatic results classification & reporting
- ✅ Seamless integration with email inboxes
- ✅ Optional integrations with **TheHive**, **MISP**, **LDAP**, **MinIO**, and Elasticsearch

---

## Features

### Multi-type Analysis

Submit and analyze:

* Emails (**.eml**, **.msg**)
* Files (PDF, Office docs, EXE, MSI, HTML, ZIP…)
* IP Addresses
* URLs
* Hashes

### Automatic Email Intake

Users can forward emails (as attachments) to a dedicated mailbox.
The **Email Feeder** ingests these messages and triggers analysis automatically.

### Smart Classification

Based on aggregated analyzer results, Suspicious classifies each submission:

| Level            | Meaning                                 |
| ---------------- | --------------------------------------- |
| **Dangerous**    | Do not open; malicious intent detected  |
| **Suspicious**   | High risk; content should not be opened |
| **Inconclusive** | Low confidence; caution required        |
| **Safe**         | Content appears trustworthy             |

### Dashboards & Reporting

* Classic overview dashboard
* Phishing campaign dashboard
* User submission history
* Detailed analyzer output and final scoring
* Automatic user notifications via email

### Integrations

* **Cortex** (required for deep analysis)
* **Elasticsearch** (search engine)
* **MinIO S3** (artifact storage)
* **TheHive** (optional incident creation)
* **MISP** (optional threat intelligence integration)
* **LDAP** (optional authentication)

---

# Architecture Overview

Suspicious is fully containerized (Docker + Docker Compose) and designed for modular deployments.

### Core Components

| Service                | Purpose                   |
| ---------------------- | ------------------------- |
| **Web (Django)**       | Main logic + frontend     |
| **Database**           | Submission storage        |
| **Elasticsearch**      | Full-text search          |
| **Cortex**             | Analyzer execution engine |
| **MinIO**              | S3 artifact storage       |
| **Email Feeder**       | Automatic inbox ingestion |
| **Traefik (optional)** | Reverse proxy / TLS       |

### Workflow

**Email Submission**

1. User forwards suspicious email as attachment
2. Email-feeder consumes mailbox & stores message in MinIO
3. Suspicious extracts headers, body, files, URLs…
4. Cortex analyzers run (YARA, sandboxing, AI header analysis, file metadata, etc.)
5. Results are aggregated and scored
6. User receives automatic response + analysis available in UI

**Web Submission**
Similar process, initiated via the web dashboard.

---

# Installation

Installation and configuration are documented in two guides:

* 👉 **Full Setup Guide:** [`SETUP.md`](SETUP.md)
* 👉 **Configuration Reference:** [`CONFIG.md`](CONFIG.md)

These documents explain:

* How to install using Docker + Docker Compose v2
* Optional Makefile shortcuts (`make up`, `make deploy`…)
* Required folder structure
* Elasticsearch gc.log requirements
* Cortex setup & API keys
* Email-feeder configuration
* Full `.env`, `settings.json`, and `config.json` documentation

---

# Quick Start

The deployment folder will help you deploy the service easily.
If using `make` (recommended):

```bash
make deploy   # pull, build, migrate, start
make up       # start services
make down     # stop services
make migrate  # run DB migrations
make backup   # database backup
```

Or with Docker Compose directly:

```bash
docker compose up -d
```

The web interface will be available at:

👉 [http://localhost:9020](http://localhost:9020)

---

# Configuration Files

Suspicious uses three main configuration files:

| File                       | Purpose                                                 |
| -------------------------- | ------------------------------------------------------- |
| `.env`                     | Environment variables for Docker services               |
| `Suspicious/settings.json` | App configuration (branding, SMTP, LDAP, Cortex, MISP…) |
| `email-feeder/config.json` | Email ingestion service (IMAP/IMAPS + MinIO + SMTP)     |

Full parameter descriptions are available in **CONFIG.md**.

---

# Screenshots

### Home Page

<img width="1845" src="https://github.com/user-attachments/assets/51a1a6cb-d58b-4175-996f-dc6cf2fc8345" />

### User Submissions

<img width="1844" src="https://github.com/user-attachments/assets/23c61439-78d4-4aa3-aa54-db8fd21a028f" />

### Submit Page

<img width="1748" src="https://github.com/user-attachments/assets/949d789b-b034-44e7-9a97-57361853c0a0" />

### Dashboard – Classic

<img width="1844" src="https://github.com/user-attachments/assets/a9b6200a-c6b5-4114-b77d-c36f3214a6af" />

### Dashboard – Phishing Campaigns

<img width="1843" src="https://github.com/user-attachments/assets/afabf61c-ba64-4b55-8343-e4df2c3061a0" />

### Settings

<img width="1843" src="https://github.com/user-attachments/assets/67548827-ca17-47f4-9d10-3f4ed8e75b4f" />

### Profile

<img width="1845" src="https://github.com/user-attachments/assets/9c57dc60-0956-4822-89e0-7eef8551efa4" />

### Admin Panel

<img width="1846" src="https://github.com/user-attachments/assets/c32f4b66-e22e-4336-b65e-312a79aaa223" />

---

# 🤝 Contributing

We welcome contributions!
Please see:

👉 [`CONTRIBUTING.md`](CONTRIBUTING.md)

This includes:

* Pull request workflow
* Coding standards (Python/Django/JS)
* Commit style
* Security best practices

---

# License

Suspicious is licensed under the **GNU Affero General Public License (AGPL)**.
Full text available in [`LICENSE`](LICENSE).

---

# Contact

For questions, issues, or feature requests:

👉 Open an issue on GitHub.
