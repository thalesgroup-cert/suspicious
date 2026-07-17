# Integrations

All integrations are configured in `settings.json`. See
[Configuration](../getting-started/configuration.md) for the full reference.

| Integration | Section | Purpose |
|---|---|---|
| Cortex | `integrations.cortex` | Analyzer execution engine (required) |
| ChromaDB | `integrations.chromadb` | Vector similarity search |
| TheHive | `integrations.thehive` | Push cases to TheHive |
| MISP | `integrations.misp` | Share indicators with MISP |
| LDAP / OIDC | `authentication.ldap` / `authentication.oidc` | Single sign-on |
| Elasticsearch | (service) | Search and indexing |
| SMTP | `email.smtp` | Outbound reporter notifications |

Each integration is optional except Cortex; leave a section's credentials blank
or `enabled: false` to disable it.
