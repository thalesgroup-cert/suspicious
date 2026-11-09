# Suspicious

**AI-powered phishing & threat-analysis platform** built by Thales Group CERT.
Suspicious automatically inspects, classifies, and reports suspicious emails,
files, URLs, IPs, and file hashes.

## What it does

- Analyzes suspicious content: emails, documents, URLs, IPs, and file hashes.
- Runs deep analysis pipelines: YARA rules, sandboxing, metadata inspection,
  Cortex analyzers, and an AI email classifier served by `ai_inference`.
- Classifies results as **Safe**, **Inconclusive**, **Suspicious**, or **Dangerous**.
- Provides full reports and dashboards through a web interface.
- Notifies reporters and integrates with TheHive, MISP, LDAP/OIDC, Elasticsearch,
  RustFS (S3) or Google Cloud Storage, and ChromaDB.

## Where to start

- **See it:** [Product demo](demo.md), a 100-second video tour
- **Run it:** [Getting Started](getting-started/quick-start.md)
- **Enable the AI classifier:** [AI inference setup and operations](getting-started/ai-inference.md)
- **Use it:** [User Guide](user-guide/submitting.md)
- **Understand it:** [Architecture](architecture.md), with service, network and analysis-flow diagrams
- **Hack on it:** [Components](components/backend/index.md) and [Contributing](contributing.md)
- **Integrate:** [API Reference](reference/rest-api.md)
