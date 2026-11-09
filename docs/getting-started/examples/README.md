# Onboarding example configs

A coherent, working example config set for a fictional org — **Meridian Group**
(CERT mailbox `suspicious@meridian.example`). These are the exact values used to
verify [`INSTALL.md`](../../../INSTALL.md) from zero.

Copy them to the real (git-ignored) paths and adjust:

| Example file | Copy to | Notes |
|---|---|---|
| `deployment-env.example` | `deployment/.env` | faithful copy of `deployment/.env.example` with Meridian dev values; keep it in sync |
| `Suspicious-settings.example.json` | `Suspicious/settings.json` | Django + integrations runtime config |
| `email-feeder-config.example.json` | `email-feeder/config.json` | IMAP mailboxes and polling; its `s3`/`mail` blocks are only used while `FEEDER_API_TOKEN` is empty |
| `suspicious-ui-env.example` | `suspicious-ui/.env` | SPA runtime branding |

**The AI vote is off in these examples.** `integrations.ai_model` ships with an
empty `token` and the connector is disabled by default. To use it, set
`AI_INFERENCE_TOKEN` in `deployment/.env` (empty in the example) and the same
value in `integrations.ai_model.token`, start `ai_inference`, then enable the
connector (see [AI inference](../ai-inference.md)).

**Two hard rules these examples encode (dev, no Vault):**

1. `Suspicious/settings.json` → `database.password` **must equal** `deployment/.env`
   → `MYSQL_PASSWORD`. With `VAULT_ADDR` unset the backend reads the DB password
   from `settings.json`.
2. `app.debug = true` so the backend is reachable over plain `http://localhost:9020`.
   With `debug = false` Django forces an HTTPS redirect and you must go through
   Traefik. Never ship `debug = true` to production.
