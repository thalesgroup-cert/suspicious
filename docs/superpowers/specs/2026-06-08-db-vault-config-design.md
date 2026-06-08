# DB-seeded runtime config + HashiCorp Vault secrets

**Date:** 2026-06-08
**Status:** Design — approved for planning
**Author:** Théo

## Problem

Today every value the platform needs at runtime lives in a single
`Suspicious/settings.json` file, bind-mounted read-only into the
container. Two pain points:

1. **No central accessor.** 21 separate modules each call
   `open(CONFIG_PATH)` + `json.load()` and slice out the section they
   need. There is no single place that owns config reads, so changing a
   value means redeploying the file, and three different env-var names
   for the path have drifted into use (`SUSPICIOUS_CONFIG_PATH`,
   `SUSPICIOUS_SETTINGS_PATH`, `CONFIG_PATH`).
2. **Secrets sit in a plaintext file.** SECRET_KEY, DB password, Cortex
   API key, MISP API key, MinIO secret key, LDAP bind password and SMTP
   password are all in the same JSON on disk, with no rotation, no
   audit, no access control.

We want: non-secret runtime config to live in the database (seeded from
`settings.json` on first launch, editable thereafter), and secrets to
live in HashiCorp Vault.

## Constraint: the boot-ordering chicken-and-egg

`suspicious/settings.py` runs at Django import time, **before any DB
connection exists**. The DB credentials and `SECRET_KEY` are needed to
*open* the database, so they cannot themselves be read from the
database. This forces config into three tiers:

| Tier | Lives in | Read when | Examples |
|---|---|---|---|
| **Bootstrap** | env vars (`deployment/.env`) | `settings.py` import | `SUSPICIOUS_CONFIG_PATH`, DB host/name/user, `VAULT_ADDR`, `VAULT_ROLE_ID`, `VAULT_SECRET_ID` |
| **Secrets** | Vault (KV v2) | lazy, first use; SECRET_KEY + DB pw at boot | SECRET_KEY, DB password, Cortex `api_key`, `webhook_secret`, MinIO `secret_key`, LDAP bind pw, SMTP password, MISP `api_key` |
| **Runtime** | DB (`settings.RuntimeConfig`), seeded from `settings.json` | request/task time via accessor | integration URLs, SMTP host/port/from/tls, Cortex analyzer list + `stale_job_timeout`, ChromaDB host, watcher enabled flag, LDAP `server_uri`/`base_dn`, branding/logo |

`settings.py` only ever touches the bootstrap + secrets tiers. It never
reads the DB at import time — that is what avoids the chicken-and-egg.

## Decisions (locked)

- **DB scope:** runtime tier only. No Vault-path indirection rows, no
  two-phase settings reload.
- **Vault deployment:** a `hashicorp/vault` container added to the
  deployment compose stack; backend, celery and email_feeder authenticate
  via **AppRole** (`role_id` + `secret_id` from env).
- **Seed + read:** an idempotent `manage.py seed_config` management
  command (run in `make deploy`) writes runtime keys into the DB; app
  code reads through a cached `get_config()` / `get_section()` accessor.
- **Dev/test fallback:** if `VAULT_ADDR` is unset, the secret client
  reads from `settings.json` exactly as today, so local dev and CI need
  no Vault and no DB-seeded config.
- **Bootstrap env vars** move from `settings.json` into
  `deployment/.env`.

## Components

### 1. Vault secret client — `suspicious/secrets.py`

- `hvac` client; AppRole login using `VAULT_ROLE_ID` / `VAULT_SECRET_ID`
  from env; reads KV v2 at `suspicious/data/<key>`.
- Public API:
  - `get_secret(key, default=None)` — in-process cache, lease aware.
- **Fail-fast at boot:** `SECRET_KEY` and DB password are fetched during
  `settings.py` import. If `VAULT_ADDR` is set but Vault is unreachable
  or the key is missing, exit with `SystemExit(1)` and a readable
  message (mirrors the existing `validate_config` fail-fast at
  `settings.py:59-63`).
- **Dev fallback:** if `VAULT_ADDR` is unset, `get_secret()` falls back
  to the matching key in `settings.json`. Zero new dependency for local
  dev / CI.

### 2. `RuntimeConfig` model — in the existing `settings` app

```python
class RuntimeConfig(models.Model):
    key        = models.CharField(max_length=200, unique=True)  # dotted, e.g. "integrations.cortex.url"
    value      = models.JSONField()                             # preserves str/int/bool/list/dict
    updated_at = models.DateTimeField(auto_now=True)
```

Lives alongside the existing DB-backed config in the `settings` app
(`Mailbox`, `EmailFeederState`, allow/deny lists). Registered in that
app's `admin.py` so values are editable from Django admin.

### 3. Seed command — `manage.py seed_config`

- Reads the runtime-tier keys out of `settings.json`, `update_or_create`
  per key. Idempotent: a second run changes nothing.
- Skips secret keys (those are provisioned into Vault separately, via
  `vault kv put` in `make init` or a `seed_secrets` helper).
- Wired into `deployment/Makefile` `deploy` target, after `migrate` and
  before the service restart.

### 4. Accessor — `settings/config.py`

- `get_config(key, default=None)` — reads Redis cache → DB →
  settings.json fallback → default. Short TTL (e.g. 60s) so admin edits
  propagate without a restart; cache invalidated on
  `RuntimeConfig.save()`. The settings.json fallback is what lets a
  dev/CI checkout with no DB seed still resolve runtime values.
- `get_section(name)` — returns a dict for a whole section (e.g.
  `"email"`, `"storage.s3"`) with **non-secret fields hydrated from DB
  and secret fields hydrated from Vault**, preserving the exact dict
  shape the call sites already expect.

This merge is the crux: most sections are *mixed* (e.g. `email` carries
both SMTP host and SMTP password; `storage.s3` carries both endpoint and
secret_key). `get_section()` merges both tiers so each call site keeps
doing `cfg["server"]`, `cfg["password"]`, `cfg["api_key"]` unchanged.

## Boot ordering

```
settings.py (import time):
    read bootstrap from env  (DB host/name/user, VAULT_ADDR, AppRole creds)
    VAULT_ADDR set?
        yes -> SECRET_KEY  = get_secret("secret_key")
               DB password = get_secret("database.password")
        no  -> read both from settings.json   (dev / CI)
    DATABASES configured -> DB connection available
    [later, at request/task time]
        get_config() / get_section() read the runtime tier from DB
```

No DB read happens at import time.

## Migration map — every settings.json read site → replacement

Source of truth for the implementation plan. 21 modules currently open
the file directly.

### Boot loader (1 site)

| Site | Now | After |
|---|---|---|
| `suspicious/settings.py:40-60` | `open → json.load → validate_config` | bootstrap from env; `SECRET_KEY` + DB pw via `get_secret()`; json fallback when no `VAULT_ADDR` |

### Secret-bearing sites → `get_secret()` / `get_section()` (Vault-backed)

| Site | Section | Secret field |
|---|---|---|
| `score_process/score_utils/thehive/client.py:40` `from_settings` | thehive | api_key |
| `score_process/score_utils/thehive/challenge.py:21,64` | thehive + email | api_key, smtp pw |
| `score_process/score_utils/thehive/phishing.py:15` | thehive | api_key |
| `score_process/misp/config_loader.py:18` | misp | api_key |
| `cortex_job/cortex_utils/cortex_and_job_management.py:28` | cortex | api_key |
| `cortex_job/cortex_utils/utils.py:8` `load_config` | cortex | api_key |
| `tasp/cron/sync_cortex.py` + `tasp/cron/utils.py:25` | cortex | api_key |
| `profiles/profiles_utils/ldap.py:13` | ldap | bind pw |
| `score_process/score_utils/send_mail/{service,final,modification,acknowledge}.py` | email | smtp pw |
| `tasp/services/challenge.py:17,23` | email + thehive | smtp pw, api_key |
| `api/views/downloads.py:33` | storage.s3 | secret_key |
| `mail_feeder/utils/email_preview/preview_jobs.py:31` | storage.s3 | secret_key |
| `mail_feeder/management/commands/regenerate_mail_previews.py:150` | storage.s3 | secret_key |
| `api/services/campaigns/chroma.py:26` | storage.s3 + chromadb | secret_key |

### Non-secret sites → `get_config()` / `get_section()` (DB-backed)

| Site | Section read |
|---|---|
| `score_process/score_utils/send_mail/*` `_load_config` / `from_settings` | email host/port/from/tls |
| `score_process/score_utils/thehive/client.py` `from_settings` | thehive url, org |
| `score_process/misp/config_loader.py` | misp url |
| `cortex_job/cortex_utils/utils.py` `load_config` → `CortexJobConfig` | cortex url, analyzers, stale_job_timeout |
| `tasp/cron/watcher.py:20` | watcher enabled flag |
| `tasp/cron/{suspicious,fetch_emails}.py` | email / cortex |
| `profiles/profiles_utils/{ldap,ciso}.py` | ldap server_uri / base_dn |
| `mail_feeder/utils/user_creation/{creation,utils}.py` | ldap / user defaults |
| `case_handler/case_utils/form_handlers/mail/mail_form.py:18` | email / branding |
| `score_process/score_utils/send_mail/email_logo.py` + `email_preview` | branding / logo |

### Per-site change shape

```python
# before
with open(CONFIG_PATH) as f:
    cfg = json.load(f).get("email", {})

# after
from settings.config import get_section
cfg = get_section("email")   # host/port from DB, password from Vault
```

Each site is a 1–2 line swap; downstream key access is untouched.

### Env-var cleanup

Collapse the three drifted path names to one. Keep
`SUSPICIOUS_CONFIG_PATH` (used by the boot loader and the dev/CI
fallback); update the `SUSPICIOUS_SETTINGS_PATH` sites
(`api/views/downloads.py`, `tasp/services/challenge.py`,
`api/services/campaigns/chroma.py`) and the `CONFIG_PATH` site
(`cortex_and_job_management.py`) to read through the accessor instead.

## Vault provisioning in deployment

- Add a `hashicorp/vault` service to `deployment/compose_apps.yaml` (or a
  dedicated compose file). Dev mode uses a fixed root token for local
  bring-up; production uses a sealed Vault with the root token held out
  of band.
- AppRole policy `suspicious-read` granting read on `suspicious/*`,
  shared by backend, celery and email_feeder.
- `make init` provisions Vault: enable KV v2 at `suspicious/`, write the
  AppRole, emit `role_id` / `secret_id` into `deployment/.env`.

## Error handling

- **Vault unreachable at boot** with `VAULT_ADDR` set → `SystemExit(1)`,
  readable message. No silent fallback to plaintext in production.
- **Missing secret key** → same fail-fast.
- **DB unreachable when reading runtime config** → `get_config()` returns
  the caller-supplied default and logs a warning; the platform degrades
  rather than crashing on a non-critical config read.
- **Cache miss** → DB read, repopulate cache.

## Testing

- **Vault client** (`secrets.py`): mock `hvac` — AppRole login, KV v2
  read, in-process cache, boot fail-fast (set `VAULT_ADDR`, force
  unreachable), dev fallback (unset `VAULT_ADDR` → reads settings.json).
- **`seed_config`**: idempotency (run twice → no duplicate rows), JSON
  type preservation (bool/int/list round-trip).
- **Accessor** (`config.py`): cache hit / miss / invalidation on save,
  default fallback on missing key, `get_section()` merge of DB + Vault
  fields into the expected dict shape.
- **Boot**: import `settings.py` with `VAULT_ADDR` set (mocked Vault) and
  unset (settings.json path); both succeed.
- **Per-site regression**: existing tests for the 21 sites must pass
  unchanged after swapping to the accessor (the dict shape is preserved
  by design). `score_process/score_utils/thehive/tests/test_phishing.py`
  already stubs `open('/app/settings.json')` — update its fixture to stub
  the accessor instead.

## Rollout (no big-bang)

1. Add `secrets.py`, `RuntimeConfig` + migration, and `config.py`
   accessor — all with the settings.json fallback. Nothing breaks; no
   call site changed yet.
2. Add `seed_config` and wire it into `make deploy`. Seed runtime config.
3. Switch the 21 read sites to the accessor, section by section, each
   behind its existing tests.
4. Provision Vault, move secrets in, drop them from `settings.json`.
   `settings.json` shrinks to the dev/CI fallback document.

## Out of scope

- The standalone `email-feeder/` service keeps its own `config.json`
  loader (`classes/services/config_service.py`); it is a separate process
  with its own lifecycle. A later iteration can point it at Vault too.
- No secret rotation automation in this iteration (Vault makes it
  possible; wiring it is follow-up work).
