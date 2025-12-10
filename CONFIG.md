# **Configuration Guide – Suspicious Platform**

Suspicious relies on several configuration files to define its infrastructure, integrations, branding, email pipeline, and service credentials.
This guide explains how each file works and how it connects to the deployment environment.

It covers:

* `.env` — core deployment configuration
* `settings.json` — Suspicious main application configuration
* `config.json` — Email Feeder configuration

The initialization script (`make init`) automatically validates and prepares many of the required files and directories.

---

# `.env` — Deployment Environment Configuration

The `.env` file defines **all runtime variables** used by Docker Compose, the initialization scripts, and the platform.

Create it manually or let the init script generate it:

```bash
cp .env.example .env
```

The content is structured into logical sections:

---

## **1. Application Versions**

```env
SUSPICIOUS_VERSION=latest
DB_SUSPICIOUS_VERSION=12
MINIO_VERSION=RELEASE.2025-04-22T22-12-26Z
CORTEX_VERSION=4.0
ELASTICSEARCH_VERSION=8.19.7
TRAEFIK_VERSION=v3.5
```

Modify versions only if you know the minimum compatibility required.

---

## **2. Application Ports**

Each service exposes one or more ports:

```env
SUSPICIOUS_PORT=9020
DB_SUSPICIOUS_PORT=3306
MINIO_PORT_1=35001
MINIO_PORT_2=35002
CORTEX_PORT=9001
ELASTICSEARCH_PORT=9200
```

Change these only if ports conflict on your host.

---

## **3. Network Configuration**

```env
DOMAIN_CORP=your.corporate.domain
NETWORK_NAME=suspicious_net
NETWORK_SUBNET=172.20.0.0/16
NETWORK_GATEWAY=172.20.0.1
NETWORK_IP_RANGE=172.20.0.0/24
```

`DOMAIN_CORP` is automatically inserted into **Traefik TLS configuration** by the init script.

---

## **4. Database Credentials**

```env
MYSQL_DATABASE=db_suspicious
MYSQL_USER=suspicious
MYSQL_PASSWORD="password"
MYSQL_ROOT_PASSWORD="rootpassword"
```

⚠️ Must be set **before first launch**.
Changing afterward requires deleting the DB volume → **data loss**.

---

## **5. MinIO Object Storage**

```env
MINIO_ROOT_USER=minio
MINIO_ROOT_PASSWORD="superpassword"
```

Used by Suspicious to store attachments, files, and message artifacts.

---

## **6. Container Names**

```env
DB_CONTAINER=db_suspicious
WEB_CONTAINER=suspicious
```

Changing these is rarely necessary.

---

## **7. Application Paths**

All local paths used by components:

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

The init script validates all of these directories and creates missing ones when possible.

---

## **8. Optional Proxy**

```env
HTTP_PROXY=
HTTPS_PROXY=
NO_PROXY=localhost
```

Leave empty unless your environment requires proxies.

---

---

# `settings.json` — Suspicious Main Application Configuration

This file defines the **internal logic** of Suspicious: branding, API keys, business rules, LDAP, Cortex settings, and more.

It is automatically created if missing:

* From `settings-sample.json`
* During `make init`

---

## **A. Core Application Settings**

```json
"allowed_host": "suspicious",
"csrf_trusted_origins": "https://localhost",
"django_debug": "True",
"django_secret_key": "django-insecure-test",
"email": "suspicious@test.com",
"tz": "Europe/Paris"
```

* Change `django_secret_key` in production.
* `django_debug` must be `False` in production.

---

## **B. Branding**

Suspicious supports full corporate branding:

```json
"footer": "Your Group",
"ico": "data:image/png;base64,...",
"logo": "data:image/png;base64,...",
"banner": "data:image/png;base64,...",
"sign": "data:image/png;base64,..."
```

You may embed **Base64** logos or host them externally.

---

## **C. Email Pattern Matching**

```json
"pattern": "pattern to match your company mail addresses"
```

Used to detect whether a sender belongs to the organization.

---

## **D. External Integrations**

Suspicious integrates with:

### **1. TheHive**

```json
"thehive": {
  "enabled": false,
  "url": "https://thehive",
  "api_key": "...",
  "the_hive_verify_ssl": false
}
```

Enable only if you want to create cases automatically.

---

### **2. Cortex**

```json
"cortex": {
  "url": "http://cortex:9001",
  "api_key": "your cortex api key",
  "header_analyzer": "MailHeader_4_0",
  "ai_analyzer": "AI_Mail_Analyzer_1_4",
  "sandbox_analyzer": "ThreatGridOnPrem_1_0",
  "yara_analyzer": "Yara_Boosted_3_2",
  "file_info_analyzer": "FileInfo_8_0"
}
```

These keys must match analyzer names installed in Cortex.

API key comes from:

* Cortex → Organization → User → API Keys

---

### **3. MISP**

```json
"misp": {
  "suspicious": { "url": "...", "key": "...", "ssl_verify": "False" },
  "security": { "url": "...", "key": "...", "ssl_verify": "False" }
}
```

Suspicious can push indicators to multiple MISP instances.

---

## **E. Company Domains**

Used for:

* allowed/verified domains
* impersonation detection
* classification

```json
"company_domains": [ "test.com" ]
```

---

## **F. Database Section**

This mirrors the `.env` database config:

```json
"database": {
  "mysql_database": "db_suspicious",
  "mysql_host": "db_suspicious",
  "mysql_password": "password"
}
```

Suspicious uses this for Django ORM settings.

---

## **G. LDAP Authentication**

Supports enterprise authentication:

```json
"ldap": {
  "auth_ldap_server_uri": "ldaps://ldap",
  "auth_ldap_base_dn": "ou=People,o=group",
  "auth_ldap_bind_dn": "...",
  "auth_ldap_bind_password": "..."
}
```

Disable SSL verification only in development.

---

## **H. Outgoing Mail Templates**

Suspicious can send:

* Acknowledgements
* Challenge messages
* Final decisions
* Branding-rich notifications

Configured under:

```json
"mail": { ... }
```

All logos support **Base64 images**.

---

---

# `config.json` — Email Feeder Configuration

The Email Feeder is responsible for:

* Connecting to mailboxes (IMAP / IMAPS)
* Fetching suspicious messages
* Storing data in MinIO
* Passing content to Suspicious for analysis

This file is located in:

```
<FEEDER_PATH>/config.json
```

If missing, it is created from `config-sample.json` during `make init`.

---

## **A. Mail Connectors**

Supports multiple connectors:

```json
"imap-dev": {
  "enable": true,
  "host": "localhost",
  "port": 3143,
  "login": "imap_user",
  "password": "imap_password",
  "mailbox_to_monitor": "INBOX"
}
```

Use `"enable": false` to disable unused profiles.

For IMAP **over TLS**:

```json
"imaps-dev": {
  "enable": true,
  "certfile": "/path/to/cert.pem",
  "rootcafile": "/path/to/rootca.pem"
}
```

---

## **B. Feeder Working Directory**

```json
"working-path": "/tmp/suspicious"
```

This directory stores:

* Temporary EML files
* Extracted metadata
* Processing queue

---

## **C. Polling Interval**

```json
"timer-inbox-emails": 10
```

Polling frequency in seconds.

---

## **D. MinIO Storage**

```json
"minio": {
  "endpoint": "localhost:9000",
  "access_key": "minioadmin",
  "secret_key": "minioadmin",
  "secure": false
}
```

This must mirror your `.env` MinIO configuration.

---

## **E. SMTP for Notifications**

These fields mirror Suspicious’s email branding:

```json
"mail": {
  "server": "localhost",
  "port": 3025,
  "username": "SUSPICIOUS",
  "logos": { ... }
}
```

---

# Additional Notes & Recommendations

### SSL/TLS

Enable SSL verification in production environments:

* `ssl_verify`
* `auth_ldap_verify_ssl`
* IMAPS certificates

### Secrets

Do NOT store secrets in Git.
Use:

* Vault
* CI/CD secret injection
* Docker secrets (future-ready)

### Branding

Replace all Base64 placeholders with real assets.

### Directory Structure

All required directories are created automatically during:

```bash
make init
```

This includes:

* Elasticsearch logs
* Cortex job dirs
* MinIO
* Certificates
* Docker config

---

# 🎉 Ready to Run

Once `.env`, `settings.json`, and `config.json` are configured:

```bash
make up
```

Your Suspicious instance will be fully operational, integrated with:

* Email ingestion
* Cortex analyzers
* MinIO object storage
* LDAP (optional)
* TheHive + MISP (optional)
