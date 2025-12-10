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

# Suspicious 🛡️

An **AI-powered phishing & threat-analysis platform** to automatically inspect, classify, and report suspicious emails, files, URLs, IPs, and hashes built for teams and organizations.

## Why Suspicious?

Phishing and social-engineering attacks are becoming more sophisticated, combining deceptive emails, malware, credential theft, malicious links, and more.

Suspicious offers a **scalable, automated, AI-augmented defense** that helps you:

- 🔎 Analyze suspicious content: emails, documents, URLs, IPs, file hashes…
- 🧠 Use deep analysis pipelines: YARA rules, sandboxing, metadata inspections, **AI-based classifier**, Cortex analyzers
- ✅ Classify results into actionable categories (Safe / Inconclusive / Suspicious / Dangerous)
- 📄 Provide full analysis reports and dashboards through an intuitive web interface
- 📤 Automatically notify or alert users via email
- 🔌 Integrate optionally with **TheHive**, **MISP**, **LDAP**, **MinIO**, **Elasticsearch**, and more

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
| `email-feeder/config.json` | Email ingestion config: IMAP/IMAPS connectors, MinIO settings, polling, working directory, notification SMTP settings |

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
  - **MinIO (S3-compatible)** for storage of artifacts
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
| **Web (Django)**   | Core logic + UI – submission, analysis, reports |
| **Database**       | Stores metadata, results, user settings |
| **Elasticsearch**  | Search engine & indexing |
| **Cortex**         | Analyzer engine (runs YARA, AI, sandbox, metadata analyzers) |
| **MinIO (S3)**     | Stores uploaded files, extracted attachments, artifacts |
| **Email Feeder**   | Monitors mailboxes, imports incoming emails automatically |
| **Traefik (optional)** | Reverse-proxy, TLS/HTTPS termination, domain routing |

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

## License

Suspicious is released under the **GNU Affero General Public License v3 (AGPL-3.0)**.

See the [`LICENSE`](LICENSE) file for full details.

## Contact & Support

Have questions, ideas, or issues?

👉 Open an [issue](https://github.com/thalesgroup-cert/suspicious/issues) feedback is very welcome!
