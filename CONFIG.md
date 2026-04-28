# Configuration Guide — Suspicious Platform

This document describes every configuration file and environment variable required to deploy and run **Suspicious**.

## Configuration Files Overview

| File | Location | Purpose |
|------|----------|---------|
| `.env` | `deployment` | Docker Compose runtime: ports, paths, credentials, versions |
| `settings.json` | `Suspicious/` | Main application: branding, behavior, integrations, mail |
| `config.json` | `email-feeder/` | Email ingestion: mailbox connectors, storage, polling, notifications |

> **`make init`** checks for these files and — if missing — creates them from sample templates (`.env.example`, `settings-sample.json`, `config-sample.json`). It also verifies directory structure, permissions, and certificates.

---

## 1. `.env` — Deployment Environment

```bash
cp .env.example .env
```

### 1.1 Application Versions

```env
SUSPICIOUS_VERSION=latest
DB_SUSPICIOUS_VERSION=12
RUSTFS_VERSION=1.0.0-alpha.90
CORTEX_VERSION=4.0.0-1
ELASTICSEARCH_VERSION=8.19.7
TRAEFIK_VERSION=v3.6
CHROMADB_VERSION=1.5.5
```

> Only update versions when you know compatibility. Mismatched versions can break services.

### 1.2 Service Ports

```env
SUSPICIOUS_PORT=9020
SUSPICIOUS_UI_PORT=9021
RUSTFS_PORT=35000        # RustFS console — local access only
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

> ⚠️ Must be set **before first startup**. Changing after initialization requires removing the database volume, which **erases all data**.

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
CORTEX_PATH=../cortex
AIANALYZER_PATH=../Analyzers/AIMailAnalyzer
CA_PATH=./certificates
TRAEFIK_PATH=../traefik
```

### 1.8 Proxy Settings

```env
HTTP_PROXY=
HTTPS_PROXY=
NO_PROXY=localhost
```

Leave blank unless your environment requires an outbound proxy.

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
| `secret_key` | Django secret key — generate with `openssl rand -base64 33` |
| `debug` | Must be `false` in production |
| `allowed_hosts` | Hostnames Django will respond to |
| `csrf_trusted_origins` | Full origins allowed to make POST requests (include scheme + host) |
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

### 2.4 Database

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

Must be consistent with `.env` `MYSQL_*` values.

### 2.5 Storage (MinIO / RustFS)

```json
"storage": {
    "backend": "local",
    "s3": {
        "endpoint": "rustfs:9000",
        "access_key": "MINIO_ACCESS_KEY",
        "secret_key": "MINIO_SECRET_KEY",
        "secure": false,
        "auto_create_bucket": true,
        "media_bucket": "suspicious-media"
    }
}
```

Set `"backend": "s3"` to use object storage. Must match `.env` `MINIO_*` credentials.

### 2.6 Integrations

#### Cortex (required for analyzers)

```json
"cortex": {
    "url": "http://cortex:9001",
    "api_key": "CHANGE_ME",
    "analyzers": {
        "header":    "MailHeader_4_0",
        "ai":        "AI_Mail_Analyzer_1_4",
        "sandbox":   "ThreatGridOnPrem_1_0",
        "yara":      "Yara_Boosted_3_2",
        "file_info": "FileInfo_8_0"
    }
}
```

Analyzer names must match exactly those installed in your Cortex instance. Generate the API key via Cortex → Organization → User → API keys.

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

### 2.7 Authentication

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
        "verify_ssl": false
    }
}
```

Configure either OIDC or LDAP (or both). For production LDAP, set `"verify_ssl": true`.

### 2.8 Company Domains

```json
"domains": ["testgroup.com"]
```

Used to identify internal senders, auto-create users, and reduce false positives on domain matching.

### 2.9 Email & Notification

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

### 2.10 Observability

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

To enable the Tempo backend in Docker Compose, run:

```bash
make monitor-up
```

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

You can define as many named connectors as needed. Set `"enable": false` to deactivate a connector without removing it.

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

## Best Practices

- **Never commit secrets** — use environment variable injection, Docker secrets, or a secrets manager in production.
- **Enable SSL/TLS everywhere in production** — IMAPS connectors, database, Cortex, MISP, TheHive.
- **Customize before first run** — set `secret_key`, `allowed_hosts`, `csrf_trusted_origins`, and branding assets before exposing the stack.
- **Back up before changing credentials** — modifying `MYSQL_*` after first run requires dropping the database volume, which erases all data.
- **Run `make init`** before `make up` on every fresh deployment to catch missing files and permission issues.

---

## Launch

Once `.env`, `settings.json`, and `config.json` are complete:

```bash
make up
```

The full stack starts: web UI, API, database, email-feeder, Cortex, MinIO/RustFS, Elasticsearch, ChromaDB, Traefik, and optional services.

---

## Related Documentation

| Document | Description |
|----------|-------------|
| [SETUP.md](./SETUP.md) | Full installation and deployment instructions |
| [deployment/README.md](./deployment/README.md) | Deployment-specific instructions |
| [README.md](./README.md) | Project overview, features, and usage |
| [CONTRIBUTING.md](./CONTRIBUTING.md) | Development and contribution guidelines |