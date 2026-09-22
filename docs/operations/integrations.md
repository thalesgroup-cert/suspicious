# Integrations

Cortex, LDAP/OIDC, and Elasticsearch are configured in `settings.json` — see
[Configuration](../getting-started/configuration.md) for the full reference.
TheHive, MISP, Watcher, SMTP, ChromaDB, and `ai_narration` are
[connectors](../components/backend/connectors.md): their `integrations.<name>`
sections are DB-backed (editable via the connector admin/API, Vault-overlaid
for secret fields) rather than static `settings.json` blocks, though a
`settings.json` value still seeds them at first boot.

| Integration | Section | Purpose |
|---|---|---|
| Cortex | `integrations.cortex` | Analyzer execution engine (required) |
| ChromaDB | `integrations.chromadb` | Vector similarity search |
| TheHive | `integrations.thehive` | Push cases to TheHive |
| MISP | `integrations.misp` | Share indicators with MISP |
| Watcher | `integrations.watcher` | Reconcile allow/deny domain lists against the Watcher service |
| `ai_narration` | `integrations.ai_narration` | Plain-language case narration (Ollama or an external LLM on the manual path; Ollama-only when it fires automatically) |
| LDAP / OIDC | `authentication.ldap` / `authentication.oidc` | Single sign-on |
| Elasticsearch | (service) | Search and indexing |
| SMTP | `email.smtp` | Outbound reporter notifications |

Each integration is optional except Cortex; leave a section's credentials blank,
`enabled: false`, or the connector disabled to turn it off.
