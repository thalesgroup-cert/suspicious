# Configuration Guide

**Suspicious** relies on several configuration files to define database access, services, authentication, and integration with external tools.
This document describes each configuration file and its main parameters.

---

## 1. Global Environment File (`.env`)

This file contains environment variables used to configure Docker services.

### Database

```env
MYSQL_DATABASE=db_suspicious       # Database name
MYSQL_HOST=db_suspicious           # Hostname of the DB container
MYSQL_USER=suspicious              # Application DB user
MYSQL_PORT=3306                    # Database port
MYSQL_PASSWORD=password            # User password
MYSQL_ROOT_PASSWORD=strongpassword # Root password (use strong values!)
```

⚠️ Credentials must be defined **before the first database initialization**.
Changing them afterward requires deleting the Docker volume, which will erase all data.

### MinIO

```env
MINIO_ROOT_USER=minio
MINIO_ROOT_PASSWORD=strongpassword
```

### Application Paths and Ports

```env
SUSPICIOUS_PATH=./Suspicious
SUSPICIOUS_PORT=8000
DB_SUSPICIOUS_PATH=./db_suspicious
ELASTICSEARCH_PATH=./elasticsearch
ELASTICSEARCH_PORT=9200
CORTEX_PATH=./cortex
CORTEX_PORT=10001
```

### Proxy (optional)

```env
HTTP_PROXY=http://proxy.com:8080
HTTPS_PROXY=http://proxy.com:8080
```

---

## 2. Suspicious Settings (`Suspicious/settings.json`)

This JSON configures the main **Suspicious** application.

### Core Application

* `allowed_host` → Hostname of the app
* `csrf_trusted_origins` → Allowed origins for CSRF protection
* `django_secret_key` → Must be unique and secret
* `email` → Default address used by the app
* `tz` → Timezone
* `pattern` → Regex pattern matching corporate email addresses
* `footer`, `link`, `ico`, `logo`, `banner`, `sign` → Custom branding

### Integrations

* **TheHive**: Incident response platform (`url`, `api_key`, SSL options, tags)
* **Cortex**: Analyzer backend (`url`, `api_key`, analyzers configuration)
* **MISP**: Threat intelligence sharing platform (API URL, keys, tags, SSL)

### Company Domains

Company domains are used for detecting users linked to your company and all allow listed subdomains to avoid impersonation

```json
"company_domains": ["testgroup.com"]
```

### Database

Redundant config (mirrors `.env`) for in-app usage: database, user, SSL, pooling.

### LDAP Authentication

* `auth_ldap_server_uri` → LDAP/LDAPS server
* `auth_ldap_base_dn` / `auth_ldap_bind_dn` / `auth_ldap_bind_password` → Bind credentials
* `auth_ldap_filter` → LDAP query to filter valid users
* `auth_ldap_verify_ssl` → Enable/disable SSL verification

### Mail

Defines SMTP server and branding for notification emails (footers, logos, links to intranet, social networks).

---

## 3. Email Feeder (`email-feeder/config.json`)

This service connects to email inboxes and ingests suspicious messages.

### Mail Connectors

Supports **IMAP** and **IMAPS**:

```json
"imap-dev": {
  "enable": false,
  "host": "imap.test",
  "port": 143,
  "login": "user@organisation.com",
  "password": "secret",
  "mailbox_to_monitor": "TEST"
}
```

```json
"imaps-dev": {
  "enable": true,
  "host": "imaps.test",
  "port": 993,
  "login": "user@organisation.com",
  "password": "secret",
  "mailbox_to_monitor": "TEST"
}
```

Multiple connectors can be defined (dev, prod, etc.).

### Processing

* `working-path` → Storage path for processed cases
* `timer-inbox-emails` → Polling interval (in seconds)

### MinIO

Object storage configuration for email attachments.

### Mail

SMTP server and templates used for sending analysis results.

---

## Recommendations

* **Security**: Always replace default passwords (`MYSQL`, `MINIO`, `LDAP`, `API keys`).
* **Branding**: Customize `logo`, `banner`, `footer`, and `mail` section to match your organization.
* **SSL/TLS**: Enable verification (`ssl_verify`, `auth_ldap_verify_ssl`) in production.
* **Secrets management**: Use a vault or environment variable injection instead of hardcoding keys.

---

👉 With these three files properly configured, **Suspicious** will be ready to run in your environment, integrated with your mail servers, Cortex analyzers, TheHive, and MISP.
