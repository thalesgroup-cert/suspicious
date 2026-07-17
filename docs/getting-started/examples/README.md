# Onboarding example configs

A coherent, working example config set for a fictional org — **Meridian Group**
(CERT mailbox `suspicious@meridian.example`). These are the exact values used to
verify [`INSTALL.md`](../../../INSTALL.md) from zero.

Copy them to the real (git-ignored) paths and adjust:

| Example file | Copy to | Notes |
|---|---|---|
| `deployment-env.example` | `deployment/.env` | image versions, ports, DB creds, paths |
| `Suspicious-settings.example.json` | `Suspicious/settings.json` | Django + integrations runtime config |
| `email-feeder-config.example.json` | `email-feeder/config.json` | IMAP/SMTP/S3 for the feeder |
| `suspicious-ui-env.example` | `suspicious-ui/.env` | SPA runtime branding |

**Two hard rules these examples encode (dev, no Vault):**

1. `Suspicious/settings.json` → `database.password` **must equal** `deployment/.env`
   → `MYSQL_PASSWORD`. With `VAULT_ADDR` unset the backend reads the DB password
   from `settings.json`.
2. `app.debug = true` so the backend is reachable over plain `http://localhost:9020`.
   With `debug = false` Django forces an HTTPS redirect and you must go through
   Traefik. Never ship `debug = true` to production.
