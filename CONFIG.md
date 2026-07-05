# Configuration Guide — Suspicious Platform

This document describes every configuration file and environment variable required to deploy and run **Suspicious**.

## Configuration Files Overview

| File | Location | Purpose |
|------|----------|---------|
| `.env` | `deployment` | Docker Compose runtime: ports, paths, credentials, versions |
| `settings.json` | `Suspicious/` | Main application: branding, behavior, integrations, mail |
| `config.json` | `email-feeder/` | Email ingestion: mailbox connectors, storage, polling, notifications |

> **`make init`** checks for these files and — if missing — creates them from sample templates (`.env.example`, `settings-sample.json`, `config-sample.json`). It also verifies directory structure, permissions, and certificates.

> **Tested baseline.** The full 13-service stack was brought up end-to-end with
> the image versions in [§1.1](#11-application-versions). Four settings decide
> whether it starts and serves traffic — get these right first:
>
> | Setting | Rule |
> |---|---|
> | `settings.json` `database.password` | must equal `.env` `MYSQL_PASSWORD` (no Vault) — [§2.5](#25-database) |
> | `settings.json` `app.debug` | `true` for plain HTTP on `localhost`; `false` forces HTTPS via Traefik — [§2.1](#21-core-application) |
> | `settings.json` `app.allowed_hosts` | include `DOMAIN_CORP`, or the Traefik path returns `DisallowedHost` — [§2.1](#21-core-application) |
> | `.env` `CORTEX_PATH` | absolute path when running Cortex — [§1.7](#17-local-paths) |

---

## 1. `.env` — Deployment Environment

```bash
cp .env.example .env
```

### 1.1 Application Versions

```env
SUSPICIOUS_VERSION=latest        # `latest` tracks main; pin a tag for prod
# UI + feeder default to SUSPICIOUS_VERSION when unset; pin independently if needed.
SUSPICIOUS_UI_VERSION=
SUSPICIOUS_FEEDER_VERSION=
DB_SUSPICIOUS_VERSION=11.4
RUSTFS_VERSION=1.0.0-alpha.90
CORTEX_VERSION=4.0.0-1
ELASTICSEARCH_VERSION=8.19.7
TRAEFIK_VERSION=v3.3.4
CHROMADB_VERSION=0.6.3
REDIS_BROKER_VERSION=9-alpine
REDIS_CACHE_VERSION=9-alpine
```

> This set was brought up together successfully. Only change versions when you
> know they are compatible — mismatched versions can break services.

### 1.2 Service Ports

```env
SUSPICIOUS_PORT=9020
SUSPICIOUS_UI_PORT=9021
MINIO_PORT=35000         # MinIO / RustFS console — local access only
CORTEX_PORT=9001
```

### 1.3 Network Configuration

```env
DOMAIN_CORP=your.corporate.domain
NETWORK_NAME=suspicious_net
NETWORK_SUBNET=172.20.0.0/16
NETWORK_GATEWAY=172.20.0.1
NETWORK_IP_RANGE=172.20.0.0/24
```

`DOMAIN_CORP` is used by Traefik for TLS/Host routing. Adjust network settings only if you need to avoid conflicts with existing Docker networks.

### 1.4 Database Credentials

```env
MYSQL_DATABASE=db_suspicious
MYSQL_USER=suspicious
MYSQL_PASSWORD="your_db_user_password"
MYSQL_ROOT_PASSWORD="your_db_root_password"
```

> ⚠️ Must be set **before first startup**. MariaDB applies these only when it
> initialises an empty data volume. Changing them later — or reusing a volume
> created with different credentials — gives `Access denied for user
> 'suspicious'`. To reset for a fresh start (this **erases all data**):
> `docker compose rm -sf db_suspicious && docker volume rm suspicious_db_suspicious_data`.
>
> `MYSQL_PASSWORD` must match `settings.json` → `database.password` (see [§2.5](#25-database)).

### 1.5 MinIO / RustFS Credentials

```env
MINIO_ROOT_USER=minio
MINIO_ROOT_PASSWORD="your_minio_password"
```

Used by both Suspicious and Email-Feeder to store attachments, artifacts, and processed data.

### 1.6 Container Names

```env
DB_CONTAINER=db_suspicious
WEB_CONTAINER=suspicious
```

### 1.7 Local Paths

```env
ROOT_PATH=../
SUSPICIOUS_PATH=../Suspicious
SUSPICIOUS_UI_PATH=../suspicious-ui
FEEDER_PATH=../email-feeder
DOCKER_PATH=../docker
YARA_PATH=../yara-rules
MISP_PATH=../misp
CORTEX_PATH=/opt/suspicious/cortex   # ABSOLUTE when running Cortex (see note)
AIANALYZER_PATH=../Analyzers/AIMailAnalyzer
CA_PATH=./certificates
TRAEFIK_PATH=../traefik
```

> **`CORTEX_PATH` must be an absolute path when the Cortex service runs.** Cortex
> mounts analyzer job directories into sibling containers through the Docker
> socket, so the host and in-container paths must be identical. A relative value
> fails at startup with `invalid mount path: '../cortex/jobs' mount path must be
> absolute`. A relative path is fine if you do not run Cortex (core dev stack).

### 1.8 Proxy Settings

```env
HTTP_PROXY=
HTTPS_PROXY=
NO_PROXY=localhost
```

Leave blank unless your environment requires an outbound proxy. These values are
also passed as **build args** to `docker compose build`, so set them before
building images on a proxy-only network — otherwise the build fails with a
`uv pip install` (PyPI) or npm connection timeout.

---

## 2. `settings.json` — Application Configuration

Created by `make init` from `settings-sample.json` if absent.

### 2.1 Core Application

```json
"app": {
    "name": "suspicious",
    "debug": false,
    "secret_key": "CHANGE_ME",
    "allowed_hosts": ["suspicious"],
    "csrf_trusted_origins": ["https://suspicious.test"],
    "timezone": "Europe/Paris",
    "log_level": "INFO"
}
```

| Key | Description |
|-----|-------------|
| `secret_key` | Django secret key. Generate with `python3 -c "import secrets; print(secrets.token_urlsafe(64))"`. The boot-time schema check rejects placeholder/short keys; use 50+ random characters. |
| `debug` | `false` in production. **Set `true` for local development** — with `false`, Django redirects to HTTPS, so `http://localhost:9020` is unreachable without Traefik. |
| `allowed_hosts` | Hostnames Django responds to (it always adds `localhost` and `127.0.0.1`). **For the Traefik/HTTPS path, include your `DOMAIN_CORP`** or requests return `DisallowedHost`. |
| `csrf_trusted_origins` | Full origins allowed to POST (scheme + host), e.g. `http://localhost:9020` for local and `https://<DOMAIN_CORP>` for the proxy. |
| `timezone` | Django timezone — affects timestamps and scheduled tasks |
| `log_level` | `DEBUG` / `INFO` / `WARNING` / `ERROR` |

### 2.2 Branding & UI

```json
"branding": {
    "company_name": "Test",
    "contact_email": "suspicious@test.com",
    "footer": "Your Group",
    "intranet_link": "https://intranet.local",
    "assets": {
        "logo": "BASE64_LOGO",
        "icon": "BASE64_ICON",
        "banner": "BASE64_BANNER",
        "signature": "BASE64_SIGNATURE"
    }
}
```

Assets accept either a `data:image/...;base64,...` string or an `https://` URL. These values drive the web UI appearance.

### 2.3 Features

```json
"features": {
    "dual_storage_write": false
}
```

| Key | Description |
|-----|-------------|
| `dual_storage_write` | Write artifacts to both local storage and MinIO simultaneously |

### 2.4 URL Analysis

```json
"url_analysis": {
    "enabled": true,
    "max_per_domain": 5,
    "reuse_ttl_days": 7,
    "shortener_domains": ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"],
    "suspicious_tlds": ["zip", "mov", "xyz", "top", "click"]
}
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Kill-switch for the URL analysis planner. Set `false` to disable URL planning globally without removing configuration. |
| `max_per_domain` | int | `5` | Maximum number of URLs analyzed per registered domain per case. Lowest-interestingness URLs beyond this cap are marked `SKIPPED`. |
| `reuse_ttl_days` | int | `7` | Cross-case result reuse window in days. A URL whose canonical key matches a prior URL with a fresh `AnalyzerReport` within this window is marked `REUSED` instead of re-analyzed. |
| `shortener_domains` | list | `["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"]` | Known URL-shortener hostnames. Matching URLs receive a +30 interestingness boost because their final destination is unknown. Overrides the built-in list when non-empty. |
| `suspicious_tlds` | list | `["zip", "mov", "xyz", "top", "click"]` | TLDs associated with phishing and abuse. URLs on these TLDs receive a +20 interestingness boost. Overrides the built-in list when non-empty. |

### 2.5 Database

```json
"database": {
    "engine": "mysql",
    "host": "db_suspicious",
    "port": 3306,
    "name": "db_suspicious",
    "user": "suspicious",
    "password": "password",
    "root_password": "strongpassword",
    "options": {
        "ssl": false,
        "connection_pooling": false,
        "persistent_connections": false
    }
}
```

`host`, `name`, and `user` must match the `.env` `MYSQL_*` values. Without Vault,
`password` here **must equal** `.env` `MYSQL_PASSWORD` — the backend reads the
database password from `settings.json` at boot when `VAULT_ADDR` is unset. A
mismatch gives `Access denied for user 'suspicious'`.

### 2.6 Storage (MinIO / RustFS)

```json
"storage": {
    "backend": "local",
    "s3": {
        "endpoint": "rustfs:9000",
        "access_key": "MINIO_ACCESS_KEY",
        "secret_key": "MINIO_SECRET_KEY",
        "secure": false,
        "auto_create_bucket": true,
        "media_bucket": "suspicious-media",
        "fast_metadata": false
    }
}
```

`"backend": "local"` (the default) stores files on the container filesystem and
does **not** require the RustFS service — handy for a minimal dev run. Set
`"backend": "s3"` to use object storage; then `secret_key` here must match the
RustFS credentials in `.env` (`MINIO_ROOT_PASSWORD`), and RustFS must be running.

#### Feeder fast metadata

`fast_metadata` (default `false`) controls the email-ingestion fast path. The
email-feeder always writes a per-email `email.json` (parsed addresses, subject,
body, headers, attachment sha256) next to each `.eml`. When `fast_metadata` is
`true`, the backend builds its `EmailDataModel` directly from that JSON —
sha256-verified against the on-disk attachments — instead of re-opening and
re-parsing the `.eml`. Any validation error, sha256 mismatch, or missing field
falls back to `parse_email`, so the worst case equals the legacy behavior.

| Value | Behavior |
|---|---|
| `false` (default) | Backend always re-parses the `.eml` (legacy). |
| `true` | Backend reads `email.json`; falls back to `parse_email` on any mismatch. |

Enable only after end-to-end parity (fast path vs `parse_email` produce
identical `Mail` rows) is green in staging.

### 2.7 Integrations

#### Cortex (required for analyzers)

```json
"cortex": {
    "url": "http://cortex:9001",
    "api_key": "CHANGE_ME",
    "webhook_secret": "CHANGE_ME_LONG_RANDOM_STRING",
    "stale_job_timeout_seconds": 86400,
    "analyzers": {
        "header":    "MailHeader_4_0",
        "ai":        "AI_Mail_Analyzer_1_4",
        "sandbox":   "ThreatGridOnPrem_1_0",
        "yara":      "Yara_Boosted_3_2",
        "file_info": "FileInfo_8_0"
    }
}
```

| Key | Type | Default | Notes |
|---|---|---|---|
| `url` | string | — | Cortex API base URL. |
| `api_key` | string | — | Cortex API key. Generate via Cortex → Organization → User → API keys. |
| `webhook_secret` | string | `""` (disabled) | Bearer token Cortex sends to `POST /api/cortex/webhook/`. Compared via `hmac.compare_digest` to defeat timing oracles. Empty → webhook returns 503; configure Cortex with the matching shared secret. |
| `stale_job_timeout_seconds` | int | `86400` (24 h) | `CaseAnalyzerJob` rows pending past this window are auto-failed by the `fail_stale_jobs` Celery task every 600 s, so cases never stall when Cortex drops a delivery. |
| `analyzers` | object | — | Analyzer names must match those installed in your Cortex instance, exactly. |

The webhook view writes `cortex_job_processed:<jobId>` into the Redis cache with a 1 hour TTL on first delivery; duplicate Cortex retries short-circuit there. The cron fallback (`update_ongoing_cases`, every 300 s) covers any delivery that is missed entirely.

#### ChromaDB (AI vector store)

```json
"chromadb": {
    "url": "http://chromadb:8000",
    "host": "chromadb",
    "port": 8000,
    "collection_name": "suspicious_mails",
    "ssl_verify": false
}
```

Used by the AI analyzer for semantic similarity search across processed mails.

#### TheHive (optional)

```json
"thehive": {
    "enabled": false,
    "url": "https://thehive",
    "api_key": "CHANGE_ME",
    "verify_ssl": false,
    "custom_field": "",
    "email_sender": "",
    "tags": "",
    "certificate_path": "/app/cert.pem",
    "user": "exemple@user.com"
}
```

Enable to automatically create cases/alerts in TheHive from Suspicious verdicts.

#### Watcher (optional)

```json
"watcher": {
    "enabled": false,
    "url": "https://watcher",
    "api_key": "CHANGE_ME",
    "timeout": 10,
    "verify_ssl": false
}
```

#### MISP (optional)

```json
"misp": {
    "default_tags": {
        "tlp": "clear",
        "pap": "clear",
        "categories": ["MalSpam", "Phishing"]
    },
    "instances": {
        "primary": {
            "url": "http://misp",
            "api_key": "CHANGE_ME",
            "ssl_verify": false,
            "ssl_ca_certs": "/etc/ssl/certs/ca-certificates.crt"
        },
        "secondary": {
            "url": "https://secondary-misp",
            "api_key": "CHANGE_ME",
            "ssl_verify": false,
            "ssl_ca_certs": "/etc/ssl/certs/ca-certificates.crt"
        }
    }
}
```

Allows pushing indicators of compromise to one or more MISP instances.

### 2.8 Authentication

```json
"authentication": {
    "oidc": {
        "server_url": "https://oidc-server",
        "client_id": "client-id",
        "client_secret": "client-secret"
    },
    "ldap": {
        "server_uri": "ldaps://ldap",
        "bind_dn": "ou=Applications,ou=Gresources,o=Group",
        "bind_password": "CHANGE_ME",
        "base_dn": "ou=People,o=group",
        "filter": "(&(mail=%(user)s)(Tpresent=true)(!(ou=admin)))",
        "verify_ssl": true
    }
}
```

Configure either OIDC or LDAP (or both).

**LDAP TLS verification.** `verify_ssl` defaults to `true` (`OPT_X_TLS_DEMAND` — full cert + hostname check). Setting it to `false` downgrades to `OPT_X_TLS_NEVER` and exposes bind credentials to any attacker on the network path; the boot logger emits a `WARNING` so the downgrade is visible in `make logs`. Use `false` only in local dev against a self-signed test LDAP, never in production. To support an internal CA, mount the CA bundle into the container and point libldap at it via the system trust store rather than disabling verification.

### 2.9 Company Domains

```json
"domains": ["testgroup.com"]
```

Used to identify internal senders, auto-create users, and reduce false positives on domain matching.

### 2.10 Email & Notification

Controls SMTP settings, email content, links, social icons, and per-template logos.

```json
"email": {
    "api_base": "https://suspicious.test/api/",
    "smtp": {
        "server": "smtp.server.local",
        "port": 25,
        "username": "smtp_user",
        "password": "smtp_password",
        "tls": true
    },
    "content": {
        "footer": "Limited Distribution",
        "team_name": "Your Cybersecurity Team",
        "global_domain": "test.com",
        "website": "https://www.test.com/en"
    },
    "links": {
        "submissions":       "https://suspicious.test/submissions",
        "security_contact":  "mailto:security@test.com",
        "security_text":     "security@test.com",
        "inquiry":           "mailto:inquiry@test.com",
        "inquiry_text":      "inquiry@test.com",
        "glossary":          "https://glossary.local"
    },
    "socials": {
        "facebook":  "https://fr-fr.facebook.com/test",
        "twitter":   "https://x.com/test",
        "instagram": "https://www.instagram.com/test",
        "linkedin":  "https://www.linkedin.com/company/test",
        "youtube":   "https://www.youtube.com/test"
    },
    "templates": {
        "acknowledgement": "Suspicious – Submission Registered",
        "review":          "Your submission n°{case_id} has been reviewed as: {result}",
        "final":           "SUSPICIOUS EMAIL ANALYSIS - Your analysis [{case_id}] is completed"
    },
    "logos": {
        "company":   "data:image/png;base64,BASE64_LOGO",
        "acknowledge": "data:image/png;base64,BASE64_LOGO",
        "final":     "data:image/png;base64,BASE64_LOGO",
        "challenge": "data:image/png;base64,BASE64_LOGO",
        "modif":     "data:image/png;base64,BASE64_LOGO"
    }
}
```

#### Key fields

| Key | Description |
|-----|-------------|
| `api_base` | Base URL used to build challenge/portal links inside emails |
| `smtp.tls` | Enable STARTTLS on the SMTP connection |
| `content.team_name` | Team name shown in email body and footer |
| `content.global_domain` | Domain shown as a global link in the email footer |
| `links.security_contact` | `mailto:` URI for the security team — used in Dangerous verdict emails |
| `links.glossary` | Link to your cybersecurity glossary, shown in all email footers |
| `links.inquiry` | `mailto:` URI shown in the footer for general questions |
| `templates.*` | Subject line templates. `{case_id}` and `{result}` are interpolated at send time |
| `logos.*` | Per-template logos. Accept `data:image/png;base64,...`, `data:image/svg+xml;base64,...`, or `https://` URLs. Outlook-safe rendering is handled automatically |

### 2.11 Observability

```json
"observability": {
    "opentelemetry": {
        "enabled": false,
        "service_name": "suspicious",
        "otlp_endpoint": "http://tempo:4318"
    }
}
```

| Key | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Enable OTel tracing. Set `true` in production. |
| `service_name` | string | `"suspicious"` | Service name shown in Tempo/Grafana. |
| `otlp_endpoint` | string | `"http://tempo:4318"` | OTLP HTTP collector URL. Use `http://tempo:4318` when Tempo runs in the monitoring Docker profile. |

**Example production configuration:**

```json
{
  "observability": {
    "opentelemetry": {
      "enabled": true,
      "service_name": "suspicious-prod",
      "otlp_endpoint": "http://tempo:4318"
    }
  }
}
```

To collect traces, set `observability.opentelemetry.enabled` to `true` (above)
and start the Tempo + Grafana stack manually from its compose files under
`deployment/docker/monitoring/` (Grafana serves on port 3000). The old
`make monitor-up` target has been removed.

## 3. `email-feeder/config.json` — Email Ingestion Service

Created by `make init` from `config-sample.json` if absent.

### 3.1 Mail Connectors (IMAP / IMAPS)

```json
"mail-connectors": {
    "imap": {
        "imap-dev": {
            "enable": true,
            "host": "localhost",
            "port": 3143,
            "login": "imap_user",
            "password": "imap_password",
            "mailbox_to_monitor": "INBOX"
        }
    },
    "imaps": {
        "imaps-dev": {
            "enable": false,
            "host": "localhost",
            "port": 3993,
            "login": "imap_user",
            "password": "imap_password",
            "certfile":    "/path/to/dev/certfile.pem",
            "keyfile":     "/path/to/dev/keyfile.pem",
            "rootcafile":  "/path/to/dev/rootcafile.pem",
            "mailbox_to_monitor": "INBOX"
        },
        "imaps-prod": {
            "enable": false,
            "host": "localhost",
            "port": 3993,
            "login": "imap_user",
            "password": "imap_password",
            "certfile":    "/path/to/prod/certfile.pem",
            "keyfile":     "/path/to/prod/keyfile.pem",
            "rootcafile":  "/path/to/prod/rootcafile.pem",
            "mailbox_to_monitor": "INBOX"
        }
    }
}
```

You can define as many named connectors as needed. Set `"enable": false` to
deactivate a connector without removing it.

> The feeder needs **at least one enabled connector**. With every connector
> disabled it logs `No mailboxes were successfully set up … Exiting` and the
> container restart-loops. This is expected when you run the stack without a
> mailbox to poll; it does not affect the backend or UI.

| Key | Description |
|-----|-------------|
| `host` / `port` | IMAP(S) server address and port |
| `login` / `password` | Mailbox credentials |
| `certfile` / `keyfile` / `rootcafile` | Client certificate paths (IMAPS only) |
| `mailbox_to_monitor` | Folder to poll — usually `INBOX` |

### 3.2 Working Directory & Polling

```json
"working-path": "/tmp/suspicious",
"timer-inbox-emails": 10
```

| Key | Description |
|-----|-------------|
| `working-path` | Temporary directory for fetched emails, attachments, and processing queue |
| `timer-inbox-emails` | Polling interval in seconds |

### 3.3 MinIO Storage

```json
"s3": {
    "endpoint":   "rustfs:9000",
    "access_key": "minioadmin",
    "secret_key": "minioadmin",
    "secure":     false
}
```

Must match `.env` `MINIO_*` values. Used to store attachments and extraction results.

### 3.4 Outgoing Mail (Notifications)

```json
"mail": {
    "tls":          true,
    "server":       "smtp_server",
    "port":         25,
    "password":     "smtp_password",
    "username":     "smtp_user",
    "footer":       "Limited Distribution",
    "group":        "Your Cybersecurity Team Name",
    "suspicious_web": "https://suspicious.test/submissions/",
    "company_name": "test.com",
    "company_url":  "https://www.test.com/en",
    "socials": {
        "facebook":  "https://fr-fr.facebook.com/test",
        "twitter":   "https://x.com/test",
        "instagram": "https://www.instagram.com/test",
        "linkedin":  "https://www.linkedin.com/company/test",
        "youtube":   "https://www.youtube.com/test"
    },
    "glossary":      "https://glossary_to_cyber_terms",
    "inquiry":       "mailto:inquiry@yourcompany.com",
    "inquiry_text":  "inquiry@yourcompany.com",
    "security":      "mailto:security@yourcompany.com",
    "security_msg":  "security@yourcompany.com",
    "logos": {
        "company":            "data:image/png;base64,BASE64_COMPANY_LOGO",
        "acknowledge-badmail": "data:image/png;base64,BASE64_BADMAIL_BANNER"
    }
}
```

This section configures the **email-feeder container's** standalone mail service (distinct from the main application's `settings.json` email section). It is used to send the bad-submission acknowledgement email when a forwarded message cannot be processed.

| Key | Description |
|-----|-------------|
| `tls` | Enable STARTTLS |
| `server` / `port` | SMTP host and port |
| `username` / `password` | SMTP credentials |
| `group` | Team name shown in the email body |
| `suspicious_web` | Portal URL linked in the footer |
| `company_name` | Domain / company identifier shown in the footer |
| `company_url` | Link for the global team name in the footer |
| `glossary` | Cybersecurity glossary URL shown in the footer |
| `inquiry` / `inquiry_text` | Contact `mailto:` URI and display label |
| `security` / `security_msg` | Security team `mailto:` URI and display label |
| `logos.company` | Company logo — accepts `data:image/png;base64,...`, `data:image/svg+xml;base64,...`, or `https://` URL. Outlook receives a text wordmark fallback automatically |
| `logos.acknowledge-badmail` | Hero banner image for the bad-submission email |

---

## Runtime config + secrets (DB + Vault)

In production, configuration is split across three tiers; `settings.json` stays
the dev/CI fallback for both.

- **Non-secret runtime config** now lives in the **database**
  (`settings.RuntimeConfig`). It is seeded from `settings.json` by
  `python manage.py seed_config` (run automatically by `make deploy`), editable
  from the Django admin, and read in code via `settings.config.get_config` /
  `settings.config.get_section`. When the DB has no seeded value, the accessor
  falls back to `settings.json`.
- **Secrets** (API keys, passwords, the Django secret key) live in **HashiCorp
  Vault** (KV v2 at `suspicious/<dotted-key>`, field `value`), read via
  `suspicious.secrets.get_secret` using AppRole auth. When `VAULT_ADDR` is unset,
  secrets fall back to `settings.json` / `settings.ci.json`. **Leave `VAULT_ADDR`
  unset for local development** — Compose defaults it to empty, so the backend
  uses the `settings.json` fallback. Set it only once Vault is provisioned;
  otherwise the backend fails fast at boot trying to reach Vault.
- **Schema caveat:** `settings.json` must still keep schema-valid dummies for
  `app.secret_key` and `database.password` even under Vault — the boot-time
  schema check requires them, and the real values are overlaid from Vault when
  `VAULT_ADDR` is set.

See [deployment/VAULT.md](./deployment/VAULT.md) for the secret map, prod
bring-up order, and the dev/CI path.

### Config authority (shared config across services)

The **config authority** is a scoped HTTP endpoint that lets backend services
pull their effective configuration at boot instead of maintaining separate
copies of shared values.

#### Scopes

| Scope | What it holds |
|-------|---------------|
| `shared` | `storage.s3`, all `email.*` sections, `branding` — values used by more than one service. Never requested directly; always merged into a real scope. |
| `backend` | Integration settings (Cortex, TheHive, MISP, ChromaDB, LDAP/OIDC) and auth config. |
| `feeder` | No feeder-specific keys yet; consumes `shared` (S3, SMTP, branding). |

`manage.py seed_config` seeds each `settings.json` section into its scope.

#### Endpoint

```
GET /api/config/{scope}/
```

Returns the effective config for `scope`: the `shared` sections merged with the
scope's own sections. Non-secret fields come from the DB; secret leaves are
overlaid from Vault. Response always carries `Cache-Control: no-store`, is
throttled at 30 req/min, and is never written to application logs.

**Auth:** Knox token whose user belongs to the Django group named after the
scope. Superusers may read any scope.

```bash
# Example — fetch the feeder scope (requires TLS via Traefik in production)
curl -s -H "Authorization: Token <feeder-token>" \
  https://suspicious.example.com/api/config/feeder/
```

#### Provisioning

```bash
# Seed config sections into the DB (already run by `make deploy`)
docker compose exec suspicious python manage.py seed_config

# Create the feeder service account and print its Knox token (run once)
docker compose exec suspicious python manage.py create_service_token feeder
```

`create_service_token feeder` creates a `svc-feeder` user in the `feeder`
group and prints a Knox token. Paste it into `deployment/.env` as
`FEEDER_API_TOKEN`.

#### Effect on the email feeder

The feeder now fetches S3 credentials, SMTP settings, and branding from
`GET /api/config/feeder/` at boot when `BACKEND_URL` and `FEEDER_API_TOKEN`
are set. It writes a last-good cache (`.config-cache.json`, mode 0600) and
falls back to it on a backend blip; with no cache and no backend it exits
immediately. As a result, the `storage`, `outgoing-mail`, and `branding`
blocks have been removed from `email-feeder/config.json` — that file now
holds only `mail-connectors`, `working-path`, and polling settings
(see [§3](#3-email-feederconfigjson-email-ingestion-service)).

---

## Best Practices

- **Never commit secrets** — use environment variable injection, Docker secrets, or a secrets manager in production.
- **Enable SSL/TLS everywhere in production** — IMAPS connectors, database, Cortex, MISP, TheHive.
- **Customize before first run** — set `secret_key`, `allowed_hosts`, `csrf_trusted_origins`, and branding assets before exposing the stack.
- **Back up before changing credentials** — modifying `MYSQL_*` after first run requires dropping the database volume, which erases all data.
- **Run `make init`** before `make up` on every fresh deployment to catch missing files and permission issues.

---

## Launch

Once `.env`, `settings.json`, and `config.json` are complete, build and start,
then initialise the database on the **first run** (the backend stays unhealthy
until migrations are applied):

```bash
docker compose build suspicious suspicious_ui
make up
make migrate
make seed-config
make createsuperuser
```

The full stack starts: web UI, API, database, email-feeder, Cortex, RustFS,
Elasticsearch, ChromaDB, Traefik, and Vault. `make seed-config` loads the
non-secret runtime config into the database (see [Runtime config + secrets](#runtime-config-secrets-db-vault)).
See [INSTALL.md](./INSTALL.md) for the step-by-step walkthrough and verification.

---

## Related Documentation

| Document | Description |
|----------|-------------|
| [INSTALL.md](./INSTALL.md) | Full installation and deployment instructions |
| [deployment/README.md](./deployment/README.md) | Deployment-specific instructions |
| [deployment/VAULT.md](./deployment/VAULT.md) | Vault secrets + DB runtime-config runbook |
| [README.md](./README.md) | Project overview, features, and usage |
| [CONTRIBUTING.md](./CONTRIBUTING.md) | Development and contribution guidelines |