<p align="center">
    <img alt="Suspicious Logo" src="/assets/suspicious-logo.png" height="330" width="260">
</p>
<p align="center">
    <strong>AI Phishing Threat Analysis Platform</strong>
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

An **AI-powered phishing & threat-analysis platform** to automatically inspect, classify, and report suspicious emails, files, URLs, IPs, and hashes built for teams and organizations.

## Why Suspicious?

Phishing and social-engineering attacks are becoming more sophisticated, combining deceptive emails, malware, credential theft, malicious links, and more.

Suspicious offers a **scalable, automated, AI-augmented defense** that helps you:

- 🔎 Analyze suspicious content: emails, documents, URLs, IPs, file hashes…
- 🧠 Use deep analysis pipelines: YARA rules, sandboxing, metadata inspections, **AI-based classifier**, Cortex analyzers
- ✅ Classify results into actionable categories (Safe / Inconclusive / Suspicious / Dangerous)
- 📄 Provide full analysis reports and dashboards through an intuitive web interface
- 📤 Automatically notify or alert users via email
- 🔌 Integrate optionally with **TheHive**, **MISP**, **LDAP**, **RustFS**, **Elasticsearch**, and more

## Getting Started (Quick Setup)

We recommend using Docker + Docker Compose v2. For full instructions, see **[SETUP.md](SETUP.md)** and **[CONFIG.md](CONFIG.md)**.

```bash
# 1. Clone the repo
git clone https://github.com/thalesgroup-cert/suspicious.git
cd suspicious/deployment

# 2. Initialize environment, configs & directory structure
make init

# 3. Start the stack
make up

# 4. On first run: run database migrations + create superuser
make migrate
make superuser

# 5. Open the web UI
#    http://localhost:9020  (or your configured domain/port)
```

Alternatively, you can use Docker Compose directly:

```bash
docker compose up -d
```

## Configuration Overview

Suspicious uses three main configuration files:

| File                       | Purpose                                                                                                               |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `.env`                     | Environment variables for Docker services (versions, ports, paths, credentials)                                       |
| `Suspicious/settings.json` | App-level config: branding, SMTP, LDAP, Cortex & MISP credentials, allowed domains, UI settings, etc.                 |
| `email-feeder/config.json` | Email ingestion config: IMAP/IMAPS connectors, RustFS settings, polling, working directory, notification SMTP settings |

For full parameter documentation and examples, refer to **[CONFIG.md](CONFIG.md)**.

## Key Features

- **Multi-type submission support**
  - Emails (`.eml`, `.msg`)
  - Files (PDF, Office docs, archives, executable, HTML, ZIP, …)
  - URLs, IP addresses, file hashes

- **Automatic email ingestion**
  - Forward suspicious emails to a monitored mailbox → ingested via Email Feeder → queued for automated analysis

- **On-demand web submissions**
  - Use the “Submit an Item” UI to send files, URLs, hashes, IPs, or email files for analysis

- **Smart classification & reporting**
  - Results are scored and categorized by risk
  - Dashboards for overall statistics, phishing-campaign overviews, user submission history, detailed analyzer outputs

- **Extensible integrations and stack support**
  - **Cortex** for analyzer execution (YARA, AI, sandboxing, metadata analysis…)
  - **Elasticsearch** for search capabilities
  - **RustFS (S3-compatible)** for storage of artifacts
  - Optional integration with **TheHive** / **MISP** for incident or threat-intel workflows
  - Optional **LDAP authentication** for enterprise setups

## AI Mail Analysis

Suspicious includes a built-in AI module (via `Analyzers/AIMailAnalyzer`) that classifies emails by intent (phishing, malicious, suspicious, benign…) complementing static rules and analyzers to deliver smarter detection tailored to your organization.

### What it does

- Uses machine-learning to identify potentially malicious or suspicious email patterns beyond heuristic or rule-based detection.
- Works alongside standard analyzers (YARA, sandbox, metadata) for a more robust analysis pipeline.
- Supports organization-specific training allowing adaptation to your internal email norms, languages, and threat landscape.
- Enables dashboards and KPIs: campaign summaries, volumes of suspicious vs safe emails, historical trends, detection stats.

### Why it matters

- Detects subtle or evolving threats which static rules may miss (e.g. social-engineering, unusual metadata)
- Provides customization you can train the model on your own data to fit company-specific patterns
- Gives visibility & analytics over time helpful for SOC, reporting, awareness, and improvement loops

### How to get started

1. Go to `Analyzers/AIMailAnalyzer/` there you’ll find training scripts and instructions.
2. Collect a representative, labeled dataset (legitimate vs phishing emails).
3. Train or retrain the model to suit your environment.
4. Deploy the trained model in Cortex alongside other analyzers.
5. Review classification results; monitor performance (precision, false-positives/negatives) and retrain periodically if needed.

> 💡 **Best practice:** Combine AI classification with other analyzers (YARA, sandbox, metadata). Never rely solely on AI for blocking/auto-response.

## Architecture Overview

| Component          | Role |
|--------------------|------|
| **Web (Django REST API)** | Core logic + UI – submission, analysis, reports. Gunicorn on port 9020. |
| **Web UI (React 19 + Vite + MUI v9)** | Frontend served by Nginx on port 9021. |
| **Celery beat + worker** | Background jobs: case finalisation, Cortex sync, stale-job rescue, KPI snapshots. Brokered by Valkey/Redis. |
| **Redis / Valkey** | Celery broker + Django cache (per-case lock, Cortex webhook jobId dedup). |
| **MariaDB 12** | Stores metadata, results, KPIs, user settings. Holds the `CaseAnalyzerJob` ledger that powers per-job Cortex webhook lookups. |
| **Elasticsearch**  | Search engine & indexing. |
| **Cortex**         | Analyzer engine (runs YARA, AI, sandbox, metadata, FileInfo). Reports back via HMAC-signed `/api/cortex/webhook/`. |
| **ChromaDB**       | Vector store used by AIMailAnalyzer for semantic similarity against past cases. |
| **RustFS (S3-compatible)** | Stores uploaded files, extracted attachments, artifacts. |
| **Email Feeder**   | Standalone Python service. Monitors IMAP/IMAPS mailboxes, imports incoming emails automatically. Runs as a non-root `feeder` UID. |
| **Traefik (optional)** | Reverse-proxy, TLS/HTTPS termination, domain routing. |
| **Tempo + Grafana (optional)** | OpenTelemetry trace store + dashboards (`make monitor-up`). Replaces the legacy Prometheus stack. |

### Cortex job lifecycle (high level)

1. Django persists the `Case`, then for every analyzer dispatch `CortexJob.run_analyzer` writes an `AnalyzerReport` *and* a `CaseAnalyzerJob` row inside a single transaction. The CAJ row pins the `(case_id, cortex_job_id)` mapping at dispatch time.
2. Cortex completes each analyzer asynchronously and posts to the HMAC-signed webhook.
3. The webhook performs an O(1) indexed lookup on `CaseAnalyzerJob` and enqueues a per-job Celery task (`process_cortex_job`), which takes a Redis lock, syncs the analyzer status, and once the case's pending-CAJ count reaches zero calls `finalise_case` to score + notify.
4. A Celery beat schedule (every 300 s) re-checks any case the webhook missed; a second beat task (every 600 s) auto-fails CAJ rows older than `STALE_JOB_TIMEOUT_SECONDS` so cases never stall forever.

The AI analyzer (from `Analyzers/AIMailAnalyzer`) is fully compatible with this architecture, allowing ML-driven detection alongside traditional analyzers.

## 🤝 Contributing

We welcome contributions! Please read **[CONTRIBUTING.md](CONTRIBUTING.md)** for coding standards, pull request flow, and guidelines.

Typical workflow:

```bash
git fork & clone
git checkout -b feature/YourFeature
# make changes
git commit -m "Add feature X"
git push
# open pull request
```

You can also open [issues](https://github.com/thalesgroup-cert/suspicious/issues) if you encounter bugs or have ideas.

## Screenshots

### Home Page

![Home page screenshot](https://github.com/user-attachments/assets/51a1a6cb-d58b-4175-996f-dc6cf2fc8345)

### User Submissions

![User Submissions](https://github.com/user-attachments/assets/23c61439-78d4-4aa3-aa54-db8fd21a028f)

### Submit Page

![Submit Page](https://github.com/user-attachments/assets/949d789b-b034-44e7-9a97-57361853c0a0)

### Dashboard Classic

![Dashboard Classic](https://github.com/user-attachments/assets/a9b6200a-c6b5-4114-b77d-c36f3214a6af)

### Dashboard Phishing Campaigns

![Dashboard Phishing Campaigns](https://github.com/user-attachments/assets/afabf61c-ba64-4b55-8343-e4df2c3061a0)

## CI/CD

Continuous integration and delivery run on GitHub Actions. Four workflows
plus Dependabot live under `.github/`.

| Workflow | Trigger | What it does |
|---|---|---|
| `ci.yml` | PR to `main`, push to `main` + `test` | Conventional-commit lint, `ruff` lint, migration-drift check, full Django test suite, email-feeder unittest, frontend (eslint + tsc + vitest browser mode + build), and a no-push build of all four images. |
| `release.yml` | push to `main` + `test`, tags `v*` | Builds and pushes all four images to GHCR with SPDX SBOM (syft) + provenance attestation. `main` → `latest` + `sha-<sha>`; `test` → `test` (staging); `v*` → semver tags. |
| `codeql.yml` | PR + push to `main`, weekly | CodeQL static analysis for Python and JavaScript/TypeScript. |
| `security.yml` | PR, weekly | Trivy filesystem scan, gitleaks secret scan, `pip-audit` (×3 requirements), `npm audit`. |
| `dependabot.yml` | weekly | Dependency updates: pip (×3), npm, docker (×4), github-actions. |

### Published images (GHCR)

| Component | Image |
|---|---|
| Django API | `ghcr.io/thalesgroup-cert/suspicious` |
| Frontend (Nginx) | `ghcr.io/thalesgroup-cert/suspicious-ui` |
| Email feeder | `ghcr.io/thalesgroup-cert/suspicious-feeder` |
| AIMailAnalyzer | `ghcr.io/thalesgroup-cert/suspicious-aimailanalyzer` |

Deployment stays manual via `deployment/Makefile` (`make deploy`); CI never
holds production credentials.

### Required status checks (branch protection on `main`)

Configure under Settings → Branches → branch protection for `main`:

- `commit-lint`
- `backend-lint`
- `migration-check`
- `backend-test`
- `feeder-test`
- `frontend`
- `docker-build (suspicious)`, `docker-build (suspicious-ui)`, `docker-build (suspicious-feeder)`, `docker-build (suspicious-aimailanalyzer)`
- `Analyze (python)`, `Analyze (javascript-typescript)`

## License

Suspicious is released under the **GNU Affero General Public License v3 (AGPL-3.0)**.

See the [`LICENSE`](LICENSE) file for full details.

## Contact & Support

Have questions, ideas, or issues?

👉 Open an [issue](https://github.com/thalesgroup-cert/suspicious/issues) feedback is very welcome!
