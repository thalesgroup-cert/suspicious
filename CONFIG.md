# Configuration Guide

**Suspicious** relies on several configuration files to define database access, services, authentication, and integration with external tools.
This document describes each configuration file and its main parameters.

**Directory Setup**

Before launching **Suspicious**, make sure the required directories exist:

```bash
cd suspicious
mkdir -p {elasticsearch,cortex}

# If your database folder is missing:
mkdir -p db
````

#### Elasticsearch Configuration

##### Log Directory and `gc.log` Requirement

Elasticsearch **will not start** unless a log directory and a `gc.log` file exist and are writable by the Elasticsearch process.

Create them as follows:

```bash
cd suspicious
mkdir -p elasticsearch/logs
touch elasticsearch/logs/gc.log
```

If this file or directory is missing, you may see errors such as:

> `Error opening log file 'logs/gc.log': Permission denied`

---

##### Why `gc.log` is Required

Elasticsearch uses Java’s Garbage Collection (GC) logging by default.
Its JVM startup options include flags such as:

```
-Xlog:gc*:file=logs/gc.log:time,uptime,level,tags
```

If the `logs/` directory or `gc.log` file cannot be created or written to, the JVM exits before Elasticsearch starts.

More details:

* [Elasticsearch JVM Settings](https://www.elastic.co/guide/en/elasticsearch/reference/current/important-settings.html)
* [JVM GC Options](https://spinscale.de/posts/2020-10-28-handling-jdk-gc-options-in-elasticsearch.html)

---

#### Cortex Configuration

##### Cortex Access

The **Cortex** service must run with the user ID `1001:1001` so that it has permission to access the Docker socket:  
`/var/run/docker.sock`

This allows Cortex and its analyzers to run containers through the Docker API.

---

##### Cortex Instance Setup

```bash
cd suspicious
touch cortex/application.conf
````

1. Follow the official [StrangeBee documentation](https://docs.strangebee.com/cortex/installation-and-configuration/) to configure `application.conf`.
2. Once Cortex is installed, create an **administrator account**.
3. Using this admin account:

   * Create an **organization**.
   * Create a **user** within that organization. This user will be used by **Suspicious** to submit jobs to Cortex.
4. Generate an **API key** for that user, then copy it into the `Cortex` section of your `Suspicious/settings.json`.

Example:

```json
{
  "cortex": {
    "api_key": "GENERATED_API_KEY",
    "url": "https://your-cortex-instance"
  }
}
```

---

#### Cortex Docker Configuration

Cortex can pull private analyzers using the `cortex/docker/config.json` file.
This file contains authentication credentials for your private Docker or GitHub registries.

Example:

```json
{
  "auths": {
    "ghcr.io": {
      "auth": "BASE64_ENCODED_TOKEN"
    }
  }
}
```

> ⚠️ Use a token with **only the required permissions**, not a full-access token.

---

#### Docker Mounts and Job Directories

When running Cortex inside a Docker container, it must mount:

* The Docker socket from the host: `/var/run/docker.sock`
* A shared directory for job files between Cortex and its analyzers

If you use a private Docker registry, configure the `docker.registry` section in `application.conf` (with username/password) according to the [official documentation](https://docs.strangebee.com/cortex/installation-and-configuration/run-cortex-with-docker/).

---

## Deployment Environment File (`.env`)

A `.env.example` file is in the repo in the deployment folder simply copy it to a `.env` that you customize with your needs 

This file contains environment variables used to configure Docker services.

### Database

```env
MYSQL_DATABASE=db_suspicious       # Database name
MYSQL_USER=suspicious              # Application DB user
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

As the proxy is optionnal you can let it empty or comment the lines in the `.env`

```env
HTTP_PROXY=http://proxy.com:8080
HTTPS_PROXY=http://proxy.com:8080
```

---

## Suspicious Settings (`Suspicious/settings.json`)

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

## Email Feeder (`email-feeder/config.json`)

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
