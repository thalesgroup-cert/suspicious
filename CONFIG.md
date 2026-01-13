# Configuration Guide Suspicious Platform

This document describes the configuration files and environment variables required to deploy and run **Suspicious**.
It explains each file’s purpose, key parameters, and recommended practices.

## Configuration Files Overview

| File / Location | Purpose |
|-----------------|---------|
| `.env` | Core environment variables used by Docker Compose and all services (paths, ports, credentials, versions) |
| `Suspicious/settings.json` | Main application settings: branding, application behavior, integrations (Cortex, TheHive, MISP, LDAP, mail), domain & security settings |
| `email-feeder/config.json` | Configuration for the email ingestion service: mailbox connectors, storage, polling, MinIO connection, notification mail settings |

> ⚠️ The `make init` command will check for the presence of these files and — if missing — create them from sample templates (`.env.example`, `settings-sample.json`, `config-sample.json`). It also verifies directory structure, permissions, certificates, and more.

## 1. `.env` Deployment Environment Configuration

Use this file to define all runtime parameters for Docker and services.

Copy sample file if you did not use the `make init` command:

```bash
cp .env.example .env
```

### 1.1 Application Versions

```env
SUSPICIOUS_VERSION=latest
DB_SUSPICIOUS_VERSION=12
MINIO_VERSION=RELEASE.2025-04-22T22-12-26Z
CORTEX_VERSION=4.0
ELASTICSEARCH_VERSION=8.19.7
TRAEFIK_VERSION=v3.5
```

Update only when you know compatibility. Mismatched versions can break services.

### 1.2 Service Ports

```env
SUSPICIOUS_PORT=9020
DB_SUSPICIOUS_PORT=3306
MINIO_PORT_1=35001
MINIO_PORT_2=35002
CORTEX_PORT=9001
ELASTICSEARCH_PORT=9200
```

Change these only if port conflicts appear on your host system.

### 1.3 Network Configuration

```env
DOMAIN_CORP=your.corporate.domain
NETWORK_NAME=suspicious_net
NETWORK_SUBNET=172.20.0.0/16
NETWORK_GATEWAY=172.20.0.1
NETWORK_IP_RANGE=172.20.0.0/24
```

* `DOMAIN_CORP` is used by the Traefik TLS/Host configuration.
* Adjust network settings if you need to isolate the stack or avoid conflicts with existing networks.

### 1.4 Database Credentials (MySQL / MariaDB)

```env
MYSQL_DATABASE=db_suspicious
MYSQL_USER=suspicious
MYSQL_PASSWORD="your_db_user_password"
MYSQL_ROOT_PASSWORD="your_db_root_password"
```

⚠️ These credentials **must be set before first startup**.

Changing them after initialization requires removing the database volume which will **erase all data**.

### 1.5 MinIO Credentials (Object Storage)

```env
MINIO_ROOT_USER=minio
MINIO_ROOT_PASSWORD="your_minio_password"
```

Used by Suspicious and Email-Feeder to store attachments, artifacts, and processed data.

### 1.6 Container Names (Optional)

```env
DB_CONTAINER=db_suspicious
WEB_CONTAINER=suspicious
```

If changed, ensure all references (in Compose files, scripts, configs) match.

### 1.7 Local Paths & Directories

```env
ROOT_PATH=../
SUSPICIOUS_PATH=../Suspicious
DB_SUSPICIOUS_PATH=../db-suspicious
FEEDER_PATH=../email-feeder
DOCKER_PATH=../docker
YARA_PATH=../yara-rules
MISP_PATH=../misp
CORTEX_PATH=../cortex
AIANALYZER_PATH=../Analyzers/AIMailAnalyzer
ELASTIC_PATH=../elasticsearch
MINIO_PATH=../minio
CA_PATH=./certificates
TRAEFIK_PATH=../traefik
```

The initialization script (`make init`) checks these directories, creates missing ones, and ensures correct permissions.

### 1.8 Optional Proxy Settings

```env
HTTP_PROXY=
HTTPS_PROXY=
NO_PROXY=localhost
```

Leave blank unless your environment requires an HTTP/HTTPS proxy.

## 2. `settings.json` — Application Configuration (Suspicious)

If this file does not exist, `make init` will copy from `settings-sample.json`.

Key configuration categories:

### 2.1 Core Application Settings

```json
{
  "allowed_host": "suspicious",
  "csrf_trusted_origins": "https://localhost",
  "django_debug": "True",
  "django_secret_key": "django-insecure-test",
  "email": "suspicious@test.com",
  "tz": "Europe/Paris"
}
```

* Replace `django_secret_key` with a secure random value in production use `openssl rand -base64 33` to generate.
* Ensure `django_debug` is set to `False` in a production environment.

### 2.2 Branding & UI Customization

```json
"footer": "Your Company Name",
"ico": "data:image/png;base64,...",
"logo": "data:image/png;base64,...",
"banner": "data:image/png;base64,...",
"sign": "data:image/png;base64,..."
```

You may embed Base64-encoded images or use external URLs. This allows corporate-branded look & feel for your deployment.

### 2.3 Email Pattern Matching

```json
"pattern": "regex_for_company_mail_addresses"
```

Used to identify internal / trusted senders by matching their email domain or address pattern.

### 2.4 External Integrations

#### 2.4.1 TheHive (optional)

```json
"thehive": {
  "enabled": false,
  "url": "...",
  "api_key": "...",
  "the_hive_verify_ssl": false
}
```

Enable if you wish Suspicious to forward alerts / create incidents in TheHive automatically.

#### 2.4.2 Cortex (required for analyzers)

```json
"cortex": {
  "url": "http://cortex:9001",
  "api_key": "your_cortex_api_key",
  "header_analyzer": "MailHeader_4_0",
  "ai_analyzer": "AI_Mail_Analyzer_1_4",
  "sandbox_analyzer": "ThreatGridOnPrem_1_0",
  "yara_analyzer": "Yara_Boosted_3_2",
  "file_info_analyzer": "FileInfo_8_0"
}
```

* Ensure that each analyzer name matches exactly those installed in your Cortex instance.
* Generate the API key via Cortex → Organization → User → API keys.

#### 2.4.3 MISP (optional)

Allows pushing indicators to one or more MISP instances:

```json
"misp": {
  "suspicious": { "url": "...", "key": "...", "ssl_verify": false },
  "security":   { "url": "...", "key": "...", "ssl_verify": false }
}
```

Configure only if you use MISP.

### 2.5 Company Domains

```json
"company_domains": [ "corp.example.com", "example.com" ]
```

Used to detect and allows to create users from legitimate internal senders, whitelist domains, and help avoid false positives when matching senders.

### 2.6 Database Access (Mirrors `.env`)

```json
"database": {
  "mysql_database": "db_suspicious",
  "mysql_host": "db_suspicious",
  "mysql_password": "your_db_password",
  "mysql_user": "suspicious",
  "mysql_port": 3306,
  "mysql_root_password": "your_root_password",
  "db_use_ssl": "NO",
  "db_use_connection_pooling": "NO",
  "db_use_persistent_connections": "NO"
}
```

Ensure consistency with `.env`. Changing these after first initialization may cause database connection issues.

### 2.7 LDAP Authentication (Optional)

```json
"ldap": {
  "auth_ldap_server_uri": "ldaps://ldap.example.com",
  "auth_ldap_base_dn": "ou=People,o=Example",
  "auth_ldap_bind_dn": "...",
  "auth_ldap_bind_password": "...",
  "auth_ldap_filter": "...",
  "auth_ldap_verify_ssl": false
}
```

Enable only if you plan to use LDAP for user authentication.
For production, strongly prefer SSL verification (`auth_ldap_verify_ssl: true`).

### 2.8 Outgoing Mail & Notification Templates

Configure SMTP settings and email templates / logos under the `"mail"` section.
Supports multiple templates (acknowledgement, final result, challenge, modification) and branding via Base64 images or external URLs.

## 3. `email-feeder/config.json` — Email Ingestion Service Configuration

This config file defines how Suspicious monitors mailboxes, how often it polls, and where it stores or delivers artifacts.

`make init` will create it from `config-sample.json` if absent.

Key sections:

### 3.1 Mail Connectors (IMAP / IMAPS)

```json
"mail-connectors": {
  "imap-dev": {
    "enable": true,
    "host": "mail.example.com",
    "port": 143,
    "login": "user",
    "password": "pass",
    "mailbox_to_monitor": "INBOX"
  },
  "imaps-dev": {
    "enable": false,
    "host": "secure-mail.example.com",
    "port": 993,
    "login": "user",
    "password": "pass",
    "certfile": "/path/to/cert.pem",
    "keyfile": "/path/to/key.pem",
    "rootcafile": "/path/to/rootCA.pem",
    "mailbox_to_monitor": "INBOX"
  }
}
```

You can define multiple connectors (dev, prod, fallback, etc.).
Set `"enable": false"` for unused connectors.

### 3.2 Working Directory & Queue Settings

```json
"working-path": "/tmp/suspicious"
"timer-inbox-emails": 10
```

* `working-path`: temporary storage for fetched emails, attachments, processing queue
* `timer-inbox-emails`: polling interval (in seconds) for checking inboxes

### 3.3 MinIO Storage (Mirrors `.env`)

```json
"minio": {
  "endpoint": "minio:9000",
  "access_key": "minioadmin",
  "secret_key": "minioadmin",
  "secure": false
}
```

Ensure values match `.env`. This lets Email Feeder store attachments and extraction results in object storage.

### 3.4 SMTP Settings for Notifications (Optional)

Configure SMTP parameters if you want Suspicious (or Email Feeder) to send out analysis results or alerts via email.
Supports full branding via logos and templates.

## Additional Recommendations & Best Practices

* **Use secure, strong credentials** never ship production secrets in the repo. Use environment variables injection, secret managers, or Docker secrets.
* **Enable SSL/TLS in production** for IMAPS, external integrations (Cortex, MISP, TheHive), database connections if needed.
* **Customize branding and domain settings before public deployment** update logos, domain names, allowed hosts, CSRF/trusted origins.
* **Backup before changing database credentials** modifying `MYSQL_*` after first run will likely result in data loss.
* **Monitor logs, permissions, and directories** ensure the initialization script (`make init`) has run and checked permissions (Elasticsearch logs, certificate directory, Docker socket permissions, etc.).

## ✅ Ready to Launch

Once your configuration files (`.env`, `settings.json`, `config.json`) are complete and valid, simply run:

```bash
make up
```

Your **Suspicious** stack will start — including web UI, database, email feeder, Cortex, MinIO, Elasticsearch, and optional services.

Feel free to revisit or adjust configurations as your environment evolves.

## Related Documentation

* [SETUP.md](./SETUP.md) Full installation and deployment instructions
* [DEPLOYMENT README.md](./deployment/README.md) Full deployment instructions
* [README.md](./README.md) Project overview, features, usage, and contribution guide
* [CONTRIBUTING.md](./CONTRIBUTING.md) Development, contribution, and coding standards
