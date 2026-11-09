# Integrations

Cortex, LDAP/OIDC, and Elasticsearch are configured in `settings.json` — see
[Configuration](../getting-started/configuration.md) for the full reference.
The ten built-in connectors (TheHive, MISP, Watcher, SMTP-notify, ChromaDB, `ai_narration`,
`case_search`, `elastic_siem`, `xsoar` and `ai_model`) are
[connectors](../components/backend/connectors.md): their `integrations.<name>`
sections are DB-backed (editable via the connector admin/API, Vault-overlaid
for secret fields) rather than static `settings.json` blocks, though a
`settings.json` value still seeds them at first boot.

| Integration | Section | Purpose |
|---|---|---|
| Cortex | `integrations.cortex` | Analyzer execution engine (required) |
| ChromaDB | `integrations.chromadb` | Vector store holding the `suspicious_mails` collection (campaign detection); the `chromadb` connector runs its daily cleanup |
| TheHive | `integrations.thehive` | TheHive alerts for challenged cases and detected phishing campaigns |
| MISP | `integrations.misp` | Share indicators with MISP |
| Watcher | `integrations.watcher` | Reconcile allow/deny domain lists against the Watcher service |
| `ai_narration` | `integrations.ai_narration` | Plain-language case narration. Fires automatically via Ollama (default) or an operator-declared OpenAI-compatible endpoint (`narration_provider = openai_compatible`); OpenAI/Anthropic/Gemini are manual-only |
| `ai_model` | `integrations.ai_model` | The mail AI verdict, served by the `ai_inference` container, plus campaign detection and label sync. Off by default. Needs `token` (must equal `AI_INFERENCE_TOKEN` in `deployment/.env`); `url` defaults to `http://ai_inference:8090`. Optional: `timeout_seconds` (20), the review-mailbox fields `imap_host`, `imap_port` (993), `imap_user`, `imap_password`, `imap_use_ssl` (true), `imap_folders`, and the scheduled-retrain fields `retrain_enabled` (false) and `retrain_interval_days` (30). Only one connector may provide `mail_ai`. See [AI / ML Analyzers](../components/analyzers.md) and the [`ai_model` app](../components/backend/ai_model.md) |
| `case_search` | `integrations.case_search` | Elasticsearch-backed substring search for the investigations page. Off by default; run `manage.py reindex_cases` before enabling. Fields: `url` (default `http://elasticsearch:9200`), `username`, `password`, `index` (default `suspicious-cases`), `timeout_seconds` (2) |
| `elastic_siem` | `integrations.elastic_siem` | Forward cases at or above `min_verdict` to Elasticsearch as ECS documents for Elastic Security. Off by default; needs `url` and an `api_key`; also `index`, `min_verdict`, `verify_tls`, `timeout_seconds`, `create_index`, `ui_base_url`. See the connectors README |
| `xsoar` | `integrations.xsoar` | Open a Cortex XSOAR incident for each finalised case at or above `min_verdict`. Off by default; needs `url` and an `api_key` (plus `api_key_id` on XSOAR 8); also `incident_type`, `min_verdict`, `create_investigation`, `skip_ref_prefix`, `verify_tls`, `timeout_seconds`, `ui_base_url`. See the connectors README |
| LDAP / OIDC | `authentication.ldap` / `authentication.oidc` | Single sign-on |
| Elasticsearch | (service) | Search and indexing; credentials come from `ES_SUSPICIOUS_USER`/`ES_SUSPICIOUS_PASSWORD` in `deployment/.env`, see [Internal service authentication](../../CONFIG.md#internal-service-authentication) |
| SMTP | `email.smtp` | Outbound reporter notifications |

Each integration is optional except Cortex; leave a section's credentials blank,
`enabled: false`, or the connector disabled to turn it off.
