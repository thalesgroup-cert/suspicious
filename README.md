<p align="center">
    <img alt="Suspicious Logo" src="/assets/suspicious-logo.png" height="330" width="260">
</p>
<p align="center">
    <strong>Phishing & threat-analysis platform</strong>
</p>

<p align="center">
    <a href="https://github.com/thalesgroup-cert/suspicious/graphs/contributors">
        <img src="https://img.shields.io/github/contributors/thalesgroup-cert/suspicious?style=for-the-badge" alt="Contributors">
    </a>
    <a href="https://github.com/thalesgroup-cert/suspicious">
        <img src="https://img.shields.io/github/stars/thalesgroup-cert/suspicious?style=for-the-badge&logo=opensourceinitiative&logoColor=white" alt="Stars">
    </a>
    <a href="https://github.com/thalesgroup-cert/suspicious/issues?q=is%3Aissue+is%3Aclosed">
        <img src="https://img.shields.io/github/issues-closed-raw/thalesgroup-cert/suspicious?style=for-the-badge&logo=github" alt="Closed Issues">
    </a>
    <a href="./LICENSE">
        <img src="https://img.shields.io/github/license/thalesgroup-cert/suspicious?style=for-the-badge&logo=opensourceinitiative&logoColor=white" alt="License">
    </a>
</p>

# Suspicious

> **Documentation:** <https://thalesgroup-cert.github.io/suspicious/>

Suspicious inspects, classifies, and reports suspicious emails, files, URLs, IPs,
and file hashes. Submit an item from the web UI or forward an email to a
monitored mailbox; Suspicious runs it through YARA rules, a sandbox, metadata
checks, and a machine-learning email classifier, then returns a scored verdict
and a full report.

Built and maintained by the [Thales Group CERT](https://www.thalesgroup.com/).

## What it does

- **Analyzes** emails (`.eml`, `.msg`), documents, archives, executables, URLs,
  IP addresses, and file hashes.
- **Scores** each submission as Safe, Inconclusive, Suspicious, or Dangerous.
- **Reports** results through a web UI with dashboards, per-analyzer output, and
  submission history.
- **Ingests** email automatically from IMAP/IMAPS mailboxes.
- **Notifies** reporters of the outcome by email.
- **Integrates** with Cortex, TheHive, MISP, LDAP, Elasticsearch, ChromaDB, and
  S3-compatible storage.

## Quick start

Requires Docker and Docker Compose v2.

```bash
git clone https://github.com/thalesgroup-cert/suspicious.git
cd suspicious

# Example configs that run as-is for local development
cp docs/getting-started/examples/deployment-env.example          deployment/.env
cp docs/getting-started/examples/Suspicious-settings.example.json Suspicious/settings.json

cd deployment
docker network create suspicious_net
docker compose build suspicious
docker compose up -d db_suspicious redis_cache redis_broker
docker compose up -d --no-deps suspicious
make migrate
make seed-config
make createsuperuser
```

Open <http://localhost:9020/admin/> and sign in.

> The example configs use throwaway local credentials. Change every secret
> before exposing the app. Full guide, the complete stack (UI, HTTPS, Cortex),
> and configuration reference: **[INSTALL.md](INSTALL.md)** and **[CONFIG.md](CONFIG.md)**.

## Configuration

Three files hold all configuration. Templates ship in the repo.

| File | Purpose |
|------|---------|
| `deployment/.env` | Image versions, ports, paths, database and storage credentials |
| `Suspicious/settings.json` | Django settings, integrations, branding, SMTP, allowed domains |
| `email-feeder/config.json` | IMAP/IMAPS mailboxes, S3 storage, polling interval |

See **[CONFIG.md](CONFIG.md)** for every parameter.

## Architecture

| Component | Role |
|-----------|------|
| **Django REST API** | Submission, analysis orchestration, reports. Gunicorn on port 9020. |
| **React UI** (React 19, Vite, MUI) | Frontend served by Nginx on port 9021. |
| **Celery worker + beat** | Background jobs: case finalisation, Cortex sync, stale-job rescue, KPI snapshots. |
| **MariaDB** | Metadata, results, KPIs. Holds the `CaseAnalyzerJob` ledger behind the Cortex webhook lookup. |
| **Valkey / Redis** | Celery broker and Django cache. |
| **Elasticsearch** | Search and indexing. |
| **Cortex** | Analyzer engine — YARA, AI, sandbox, metadata, FileInfo. Reports back via an HMAC-signed webhook. |
| **ChromaDB** | Vector store for semantic similarity against past cases. |
| **RustFS** (S3-compatible) | Stores uploads, attachments, artifacts. |
| **Email Feeder** | Polls IMAP/IMAPS mailboxes and imports emails. Runs as a non-root user. |
| **Traefik** | Reverse proxy and TLS termination. |
| **Vault** | Production secret storage. |

### How an analysis runs

1. Django creates a `Case`. For each analyzer it writes an `AnalyzerReport` and a
   `CaseAnalyzerJob` row in one transaction, pinning the `(case, cortex job)`
   mapping at dispatch.
2. Cortex runs each analyzer and posts to the HMAC-signed webhook on completion.
3. The webhook looks up the case in `CaseAnalyzerJob`, then enqueues a Celery
   task that takes a per-case lock, updates the job, and calls `finalise_case`
   once the case has no pending jobs left.
4. `finalise_case` scores the case, pushes to TheHive/MISP if configured, queries
   ChromaDB for similar past cases, and emails the reporter.
5. Celery beat re-checks any webhook the platform missed (every 300 s) and fails
   jobs stuck past `STALE_JOB_TIMEOUT_SECONDS` (every 600 s), so cases never stall.

## AI email classifier

`Analyzers/AIMailAnalyzer` classifies emails by intent (phishing, malicious,
suspicious, benign) using a Sentence-Transformers embedding model and a custom
classifier, with ChromaDB for similarity search. It runs as a Cortex analyzer
alongside the static rules.

To train it on your own data:

1. Open `Analyzers/AIMailAnalyzer/` for the training scripts.
2. Prepare a labeled dataset (legitimate vs phishing).
3. Train the model.
4. Deploy it in Cortex with the other analyzers.
5. Review precision and false-positive rates; retrain as needed.

Use it alongside YARA, sandbox, and metadata analyzers. Do not auto-block on the
classifier alone.

## Contributing

See **[CONTRIBUTING.md](CONTRIBUTING.md)** for coding standards and the pull
request flow.

```bash
git checkout -b feature/your-feature
# make changes, commit, push
# open a pull request
```

Bug reports and ideas are welcome in [issues](https://github.com/thalesgroup-cert/suspicious/issues).

## Screenshots

### Login Page

![Login page screenshot](https://github.com/user-attachments/assets/369bb27e-d599-4ce2-8d3b-19a7907118cf)

### Home Page

![Home page screenshot](https://github.com/user-attachments/assets/6ef12c50-aa1b-40bc-97cc-0cf44ea5619c)

### User Submissions

![User Submissions](https://github.com/user-attachments/assets/ff902bf9-b901-4e74-a93a-4f34075268d4)

### Submit Page

![Submit Page](https://github.com/user-attachments/assets/3e48d701-ecf8-44aa-9ef0-be376d86540f)

### Profile Page

![Profile Page](https://github.com/user-attachments/assets/fc75cdff-45d6-4f28-8018-62178408bb23)

### Dashboard Classic

![Dashboard Classic](https://github.com/user-attachments/assets/d1029844-e216-4701-93f6-afaef04764fb)

### Dashboard Phishing Campaigns

![Dashboard Phishing Campaigns](https://github.com/user-attachments/assets/ef83f242-46c0-43ee-ae58-11064b51f681)

## CI/CD

GitHub Actions runs six workflows plus Dependabot under `.github/`.

| Workflow | Trigger | Runs |
|----------|---------|------|
| `ci.yml` | PRs and pushes to `main`/`test` | commit-lint, `ruff`, migration-drift check, Django tests, feeder tests, frontend (eslint + tsc + vitest + build), image builds |
| `e2e-deploy.yml` | PRs, pushes to `main`/`feature/frontweb` | full-stack deploy smoke test against a stubbed Cortex |
| `docs.yml` | PRs and pushes to `main` | builds the MkDocs site and deploys it to GitHub Pages |
| `release.yml` | pushes to `main`/`test`, `v*` tags | builds and pushes images to GHCR with SBOM and provenance |
| `codeql.yml` | PRs, pushes to `main`, weekly | CodeQL for Python and JS/TS |
| `security.yml` | PRs, weekly | Trivy, gitleaks, `pip-audit`, `pnpm audit` |

### Published images (GHCR)

| Component | Image |
|-----------|-------|
| Django API | `ghcr.io/thalesgroup-cert/suspicious` |
| Frontend | `ghcr.io/thalesgroup-cert/suspicious-ui` |
| Email feeder | `ghcr.io/thalesgroup-cert/suspicious-feeder` |

Deployment is manual via `deployment/Makefile` (`make deploy`); CI never holds
production credentials.

## License

Released under the **Apache License, Version 2.0**. See [`LICENSE`](LICENSE).

## Contact

Questions, ideas, or bugs: open an
[issue](https://github.com/thalesgroup-cert/suspicious/issues).
