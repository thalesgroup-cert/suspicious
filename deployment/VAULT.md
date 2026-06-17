# Vault & Runtime Config Runbook

Suspicious splits its configuration into three tiers. Knowing which tier owns a
value tells you where to change it and how it is loaded at boot.

| Tier | Holds | Source of truth | Loaded by |
|------|-------|-----------------|-----------|
| **Bootstrap** | Ports, image versions, network, Vault AppRole IDs, DB/MinIO bootstrap creds | `deployment/.env` | Docker Compose |
| **Secrets** | API keys, passwords, the Django secret key | HashiCorp Vault (KV v2 at `suspicious/<dotted-key>`, field `value`) | `suspicious.secrets.get_secret` via AppRole |
| **Runtime config** | Non-secret application settings (branding, integrations URLs, analyzer names, email content, …) | Database (`settings.RuntimeConfig`), seeded from `settings.json` | `settings.config.get_config` / `get_section` |

`settings.json` remains the **dev/CI fallback** for both secrets and runtime
config. When `VAULT_ADDR` is unset, secrets are read straight from
`settings.json`; when the DB has not been seeded, runtime config falls back to
`settings.json` too. No Vault server or DB seed is required to run the tests.

---

## The secret map

These twelve keys are stored in Vault and overlaid onto the matching
`settings.json` paths at boot when `VAULT_ADDR` is set. Each lives at KV v2 path
`suspicious/<dotted-key>` with a single field, `value`.

| Vault path (`suspicious/…`) | settings.json path | Required |
|---|---|---|
| `app.secret_key` | `app.secret_key` | yes |
| `database.password` | `database.password` | yes |
| `integrations.cortex.api_key` | `integrations.cortex.api_key` | yes |
| `integrations.cortex.webhook_secret` | `integrations.cortex.webhook_secret` | yes |
| `storage.s3.secret_key` | `storage.s3.secret_key` | yes |
| `integrations.thehive.api_key` | `integrations.thehive.api_key` | optional |
| `integrations.misp.instances.primary.api_key` | `integrations.misp.instances.primary.api_key` | optional |
| `integrations.misp.instances.secondary.api_key` | `integrations.misp.instances.secondary.api_key` | optional |
| `integrations.watcher.api_key` | `integrations.watcher.api_key` | optional |
| `authentication.ldap.bind_password` | `authentication.ldap.bind_password` | optional |
| `authentication.oidc.client_secret` | `authentication.oidc.client_secret` | optional |
| `email.smtp.password` | `email.smtp.password` | optional |

Optional secrets that are not set are written empty by the seeder.

---

## Production bring-up order

Run from `deployment/`. Vault uses file storage and starts **sealed** on every
boot, so the unseal step is mandatory.

1. **`make init`** — network, TLS certs, config files (creates `settings.json`
   from the sample if absent).
2. **`make up`** — start the stack (including the Vault container).
3. **Initialise + unseal Vault** (first boot only initialises). Vault runs as a
   Compose service, so run its CLI inside the container:
   ```bash
   docker compose --env-file .env exec vault vault operator init    # record the unseal keys + root token SECURELY
   docker compose --env-file .env exec vault vault operator unseal   # repeat with the threshold number of keys
   ```
   On every subsequent restart Vault comes up sealed — re-run the `operator
   unseal` command after each `make up`/restart.
4. **Export the root token** for the provisioning + seeding steps (the `make`
   targets run the vault CLI inside the container for you, so only the token is
   needed on the host):
   ```bash
   export VAULT_TOKEN=<root-token>
   ```
5. **`make provision-vault`** — enables KV v2 + AppRole, writes the
   `suspicious-read` policy, and appends `VAULT_ROLE_ID` / `VAULT_SECRET_ID` to
   `deployment/.env` (the app authenticates with these, not the root token).
6. **Export the secret values and seed them:**
   ```bash
   export SECRET_KEY=...            # required
   export DB_PASSWORD=...           # required
   export CORTEX_API_KEY=...        # required
   export CORTEX_WEBHOOK_SECRET=... # required
   export S3_SECRET_KEY=...         # required
   # optional — export only those you use:
   export THEHIVE_API_KEY=... MISP_PRIMARY_API_KEY=... MISP_SECONDARY_API_KEY=...
   export WATCHER_API_KEY=... LDAP_BIND_PASSWORD=... OIDC_CLIENT_SECRET=... SMTP_PASSWORD=...
   make seed-vault-secrets
   ```
   Values come from the environment only — never from a committed file.
7. **`make deploy`** — runs migrations and `seed_config` (loads non-secret
   runtime config from `settings.json` into `settings.RuntimeConfig`). After
   this, edit runtime config in the Django admin rather than in `settings.json`.

The app now reads secrets from Vault via the AppRole and runtime config from the
DB. Restarting the stack later requires only re-unsealing Vault (step 3).

---

## Editing connector secrets from the UI

Admins can set/rotate connector secrets (`integrations.*` — cortex, thehive,
misp, watcher) from the Settings UI, which writes straight to Vault.
`make provision-vault` already grants this — the `suspicious-read` policy it
writes includes scoped create/update on the integration secret paths:

```hcl
path "suspicious/data/integrations/*" {
  capabilities = ["create", "update", "read"]
}
```

Everything else stays read-only. If you tightened the policy by hand and removed
this stanza, the UI feature stops working as follows:

- **`create`/`update` missing** → UI save returns **502 secret store write
  failed** (Vault rejects the write).
- **No Vault at all** (`VAULT_ADDR` unset, e.g. local dev) → UI save returns
  **409 secret store not configured**; set these secrets in `settings.json` as
  before.

Boot-critical secrets (`app.secret_key`, `database.password`) and non-connector
sections (s3, ldap, oidc, smtp) are **not** editable from the UI by design —
they stay Vault/ops-only.

---

## Dev / CI path

Leave **`VAULT_ADDR` unset**. No Vault and no DB seed are needed:

- Secrets fall back to `settings.json` (or `settings.ci.json` under the test
  settings).
- Runtime config falls back to `settings.json`.

This is exactly how the unit test suite runs.

---

## Schema caveat: keep dummy secrets in `settings.json`

`suspicious.config_schema.validate_config` runs at boot against `settings.json`
and **requires** `app.secret_key` and `database.password` to be present and
non-trivial — even when the real values come from Vault. The schema cannot tell
that Vault will supply them, so `settings.json` must keep schema-valid dummies:

- **`app.secret_key`** — a string that is either ≥ 50 characters **or** contains
  no placeholder sentinel (`changeme`, `placeholder`, `secret`,
  `django-insecure`). A 50+ character non-sentinel dummy passes.
- **`database.password`** — any non-empty string.

When `VAULT_ADDR` is set, these dummies are ignored at runtime: the real
`app.secret_key` and `database.password` are pulled from Vault and overlaid
before Django uses them. The dummies exist solely to satisfy the boot-time
schema check.

The operator's real `settings.json` is **gitignored**; blank the other secret
fields there and provision them in Vault.

---

## Secret rotation

Out of scope for now. Vault makes rotation possible (re-`put` a key, restart the
app to pick up the new value), but automated rotation / lease renewal wiring is
a follow-up. Today, rotating a secret means: update the value in Vault, then
restart the app containers so they re-read it at boot.
