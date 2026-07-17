# Migrating from v1.3.8

This covers upgrading an existing `thalesgroup-cert/suspicious` **v1.3.8** deployment
to the current `main` on this fork (the React/Vite frontend rewrite, the contrib
connector framework, the rebuilt scoring engine, the `CaseAnalyzerJob` Cortex
re-architecture, and Vault secret management — see [`CHANGELOG.md`](CHANGELOG.md)
for the full list of what changed and why).

This is a breaking upgrade: `Suspicious/settings.json`'s schema was fully
restructured, six new services join the stack, and the old server-rendered
frontend is gone. Budget a maintenance window — this isn't a rolling upgrade.

## Before you start

```bash
cd deployment
make backup-db
cp .env .env.v1.3.8.bak
cp ../Suspicious/settings.json ../Suspicious/settings.json.v1.3.8.bak
cp ../email-feeder/config.json ../email-feeder/config.json.v1.3.8.bak
```

Keep the old images around (`docker image ls | grep suspicious`) until you've
verified the new deployment — see [Rollback](#rollback) below.

## What changed, at a glance

- **Frontend**: the old Django-templated UI (jQuery/Bulma/FontAwesome) is gone,
  replaced by a `suspicious-ui` service (React 19 + Vite) on its own port.
- **`Suspicious/settings.json`**: every top-level key was renamed and
  regrouped (`suspicious`/`thehive`/`cortex`/`misp`/`minio`/`ldap`/`mail` →
  `app`/`branding`/`integrations.*`/`storage`/`authentication`/`email`). See
  [Remapping settings.json](#remapping-settingsjson) below — nothing here is
  additive, your old file will not load as-is.
- **New services**: `suspicious_celery` (Celery split out of the `suspicious`
  container), `redis_broker` + `redis_cache`, `chromadb` (similarity search),
  `vault` (optional secret management).
- **`email-feeder/config.json`**: the `minio` key is renamed to `s3` (same
  fields). Everything else (`mail-connectors`, `working-path`,
  `timer-inbox-emails`) is unchanged and still valid.
- **New required secret**: `integrations.cortex.webhook_secret` — an HMAC key
  shared with Cortex to verify webhook callbacks. Generate one and configure
  it on both sides (see below); it defaults to empty, which is not secure.
- **Connectors**: TheHive/MISP/Watcher/SMTP-notify moved to a pluggable
  contrib-connector architecture. Functionally equivalent, config fields are
  renamed (see the mapping table) but the same integrations are supported.

## Step 1 — Pull and diff your `.env`

```bash
git pull
diff deployment/.env deployment/.env.example
```

Merge in what's new. The fields that actually matter for migration (not just
new optional tuning knobs):

| Variable | Notes |
|---|---|
| `SUSPICIOUS_UI_PORT` | New — port for the React frontend (default `9021`) |
| `SUSPICIOUS_UI_PATH` | New — must point at `../suspicious-ui` |
| `SUSPICIOUS_UI_VERSION`, `SUSPICIOUS_FEEDER_VERSION` | Optional; default to `SUSPICIOUS_VERSION` |
| `CHROMADB_VERSION` | New — required, `chromadb` is a new service |
| `REDIS_BROKER_VERSION`, `REDIS_CACHE_VERSION` | New — required, two new services |
| `BACKEND_URL`, `FEEDER_API_TOKEN` | New, optional — see [Step 3](#step-3--feeder-config) |
| `VAULT_ADDR`, `VAULT_ROLE_ID`, `VAULT_SECRET_ID` | New, optional — leave unset to keep secrets in `settings.json` |
| `CORTEX_NO_PROXY` | New if you're behind a corporate proxy — Cortex's k8s client rejects `*` wildcards in `NO_PROXY`, so it reads this separately |

`RUSTFS_*` was already present in v1.3.8 (the MinIO→RustFS migration predates
this guide) — nothing to do there. If you're somehow still on MinIO, see
[`deployment/Migration_from_MinIO_to_RustFS.md`](deployment/Migration_from_MinIO_to_RustFS.md) first.

## Step 2 — Remapping `settings.json`

There is no automatic converter — the schema changed too much for a safe
one-shot script. Copy `Suspicious/settings-sample.json` as your new base and
transcribe your old values across using the table in the
[reference appendix](#appendix-full-key-mapping) below.

Two things that are **not** a rename and need real values, not a copy-paste:

- **`integrations.cortex.webhook_secret`** — did not exist in v1.3.8. Generate
  one (e.g. `openssl rand -hex 32`) and set the *same* value in Cortex's own
  webhook configuration. Without it, the webhook path runs unauthenticated.
- **`integrations.chromadb.*`** — new section, required now that ChromaDB is
  a builtin connector. Point it at the new `chromadb` service
  (`host: chromadb`, `port: 8000` by default).

## Step 3 — Feeder config

`email-feeder/config.json`: rename the top-level `minio` key to `s3` (fields
inside are unchanged — `endpoint`, `access_key`, `secret_key`, `secure`).
Everything else in the file (`mail-connectors.*`, `working-path`,
`timer-inbox-emails`) still loads as-is.

Optional but recommended: switch the feeder to **config-authority mode**,
where it pulls its mail/branding config from the Django backend instead of
its own local file, so you don't maintain both:

```bash
docker compose exec suspicious python manage.py create_service_token feeder
```

Paste the resulting token into `BACKEND_URL`/`FEEDER_API_TOKEN` in
`deployment/.env`. Leave both blank to keep the feeder on its local config —
that path still works.

## Step 4 — Bring up the new services

```bash
cd deployment
docker compose --env-file .env build suspicious suspicious_ui feeder
docker compose --env-file .env up -d redis_cache redis_broker chromadb
docker compose --env-file .env up -d suspicious suspicious_celery suspicious_ui
```

`suspicious_celery` is new — Celery used to run inside the main `suspicious`
container in v1.3.8. Confirm the old container isn't still also running a
worker (check `docker compose exec suspicious ps aux` for a stray `celery`
process before removing the old image).

## Step 5 — Run migrations

```bash
docker compose --env-file .env exec suspicious python manage.py migrate
```

There are a large number of new migrations (scoring engine tables, the
`CaseAnalyzerJob` ledger, `ConnectorState`/`ConnectorDelivery`, `RuntimeConfig`).
Expect this to take longer than a typical `migrate` run; it's still a single
forward pass, not a data backfill you need to script yourself.

## Step 6 — Frontend cutover

The old server-rendered pages are gone — there's no side-by-side mode. Point
your reverse proxy at the new `suspicious_ui` service on
`SUSPICIOUS_UI_PORT` (default `9021`) alongside the existing API port. Copy
`suspicious-ui/.env.example` to `suspicious-ui/.env` and set the branding
variables — this is read at container start (no rebuild needed to change it
later).

## Step 7 — Optional: Vault

If you want secrets out of `settings.json` entirely, see
[`deployment/VAULT.md`](deployment/VAULT.md) for the bring-up + `make
provision-vault` / `make unseal` flow. This is opt-in — leaving `VAULT_ADDR`
unset keeps everything reading from `settings.json` exactly like v1.3.8 did.

## Verify

```bash
make status
curl --noproxy '*' http://localhost:9020/api/health/
```

Expect `{"status": "ok", "checks": {"db": true, "redis": true, "cortex": true}}`.
Submit one test email end-to-end (feeder → case → finalise → notify) before
decommissioning the old deployment.

## Rollback

Restore `.env`, `settings.json`, and `config.json` from the `.bak` copies made
in [Before you start](#before-you-start), `docker compose down`, retag the old
images back to the versions you were running, and `make restore-db` from the
backup taken before migrating. There is no forward-then-back migration path
for the Django schema changes — restoring the DB backup is the only supported
way back once you've run `migrate`.

## Appendix: full key mapping

`Suspicious/settings.json`, old key → new key. Fields not listed here kept the
same leaf name, just moved under a new parent (e.g. all of `mail.socials.*` →
`email.socials.*` unchanged).

| v1.3.8 | Current |
|---|---|
| `suspicious.django_debug` | `app.debug` |
| `suspicious.django_secret_key` | `app.secret_key` |
| `suspicious.trace_level` | `app.log_level` |
| `suspicious.tz` | `app.timezone` |
| `suspicious.company` | `branding.company_name` |
| `suspicious.footer` | `branding.footer` |
| `suspicious.link` | `branding.intranet_link` |
| `suspicious.ico` | `branding.assets.icon` |
| `suspicious.logo` | `branding.assets.logo` |
| `suspicious.banner` | `branding.assets.banner` |
| `suspicious.sign` | `branding.assets.signature` |
| `suspicious.oidc_server_url` | `authentication.oidc.server_url` |
| `suspicious.oidc_client_id` | `authentication.oidc.client_id` |
| `suspicious.oidc_client_secret` | `authentication.oidc.client_secret` |
| `suspicious.storage_backend` | `storage.backend` |
| `suspicious.minio_media_bucket` | `storage.s3.media_bucket` |
| `suspicious.storage_dual_write` | `features.dual_storage_write` |
| `thehive.enabled` | `integrations.thehive.enabled` |
| `thehive.url` | `integrations.thehive.url` |
| `thehive.api_key` | `integrations.thehive.api_key` |
| `thehive.the_hive_verify_ssl` | `integrations.thehive.verify_ssl` |
| `thehive.the_hive_custom_field` | `integrations.thehive.custom_field` |
| `thehive.the_hive_email_sender` | `integrations.thehive.email_sender` |
| `thehive.the_hive_tags` | `integrations.thehive.tags` |
| `thehive.certificate_path` | `integrations.thehive.certificate_path` |
| `thehive.user` | `integrations.thehive.user` |
| `cortex.url` | `integrations.cortex.url` |
| `cortex.api_key` | `integrations.cortex.api_key` |
| `cortex.header_analyzer` | `integrations.cortex.analyzers.header` |
| `cortex.ai_analyzer` | `integrations.cortex.analyzers.ai` |
| `cortex.sandbox_analyzer` | `integrations.cortex.analyzers.sandbox` |
| `cortex.yara_analyzer` | `integrations.cortex.analyzers.yara` |
| `cortex.file_info_analyzer` | `integrations.cortex.analyzers.file_info` |
| *(none — new)* | `integrations.cortex.webhook_secret` **(generate, don't skip)** |
| *(none — new)* | `integrations.chromadb.*` **(new, required)** |
| *(none — new)* | `integrations.watcher.*` (new connector, optional) |
| `database.mysql_database` | `database.name` |
| `database.mysql_host` | `database.host` |
| `database.mysql_port` | `database.port` |
| `database.mysql_user` | `database.user` |
| `database.mysql_password` | `database.password` |
| `database.mysql_root_password` | `database.root_password` |
| `database.db_use_ssl` | `database.options.ssl` |
| `database.db_use_connection_pooling` | `database.options.connection_pooling` |
| `database.db_use_persistent_connections` | `database.options.persistent_connections` |
| *(none — new)* | `database.replica.*` (optional read replica, R6) |
| `ldap.auth_ldap_base_dn` | `authentication.ldap.base_dn` |
| `ldap.auth_ldap_bind_dn` | `authentication.ldap.bind_dn` |
| `ldap.auth_ldap_bind_password` | `authentication.ldap.bind_password` |
| `ldap.auth_ldap_filter` | `authentication.ldap.filter` |
| `ldap.auth_ldap_server_uri` | `authentication.ldap.server_uri` |
| `ldap.auth_ldap_verify_ssl` | `authentication.ldap.verify_ssl` |
| `misp.tags.tlp` / `.pap` | `integrations.misp.default_tags.tlp` / `.pap` |
| `misp.suspicious.*` | `integrations.misp.instances.primary.*` |
| `misp.security.*` | `integrations.misp.instances.secondary.*` |
| `minio.access_key` | `storage.s3.access_key` |
| `minio.endpoint` | `storage.s3.endpoint` |
| `minio.secret_key` | `storage.s3.secret_key` |
| `minio.secure` | `storage.s3.secure` |
| `minio.minio_auto_create_bucket` | `storage.s3.auto_create_bucket` |
| `mail.tls` | `email.smtp.tls` |
| `mail.server` | `email.smtp.server` |
| `mail.port` | `email.smtp.port` |
| `mail.username` | `email.smtp.username` |
| `mail.password` | `email.smtp.password` |
| `mail.footer` | `email.content.footer` |
| `mail.submissions` | `email.links.submissions` |
| `mail.security` | `email.links.security_contact` |
| `mail.security_msg` | `email.links.security_text` |
| `mail.glossary` | `email.links.glossary` |
| `mail.inquiry` / `.inquiry_text` | `email.links.inquiry` / `.inquiry_text` |
| `mail.logos.*` | `email.logos.*` (unchanged sub-keys) |
| `mail.group`, `mail.global`, `mail.global_url`, `mail.suspicious_web` | Likely `email.content.team_name` / `.global_domain` / `.website` — **verify against the rendered email templates before relying on this one**, the correspondence wasn't confirmed against consuming code the way the rest of this table was |
| `email_subjects.acknowledgement` / `.review` / `.final` | `email.templates.acknowledgement` / `.review` / `.final` |
| *(none — new)* | `url_analysis.*` (on-demand URL re-analysis feature) |

`email-feeder/config.json`: only `minio` → `s3` (same fields). Everything
else unchanged.
