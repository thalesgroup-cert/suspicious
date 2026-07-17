# MinIO → RustFS Migration Guide

## Overview

**Rationale**

The open-source edition of MinIO is no longer maintained and does not receive security updates. Continuing to run it introduces increasing security risk.

RustFS is a drop-in, S3-compatible replacement:

* Written in Rust
* Apache License 2.0
* Compatible with existing MinIO data and APIs

**Migration scope**

This migration is effectively a **service swap**:

* No data migration required
* Same volume reused
* Same S3 API
* Only image, service name, and environment variables change

---

## 1. Update `compose_databases.yaml`

Replace the existing `minio` service with:

```yaml
rustfs:
  restart: always
  expose:
    - "9000"
  ports:
    - "127.0.0.1:${MINIO_PORT:-35000}:9001"
  environment:
    RUSTFS_ACCESS_KEY: ${MINIO_ROOT_USER}
    RUSTFS_SECRET_KEY: ${MINIO_ROOT_PASSWORD}
    RUSTFS_VOLUMES: /data
    RUSTFS_ADDRESS: 0.0.0.0:9000
    RUSTFS_CONSOLE_ENABLE: "true"
    RUSTFS_CONSOLE_ADDRESS: 0.0.0.0:9001
  volumes:
    - "minio_data:/data:Z"
  security_opt:
    - no-new-privileges:true
  networks:
    - suspicious_network
```

**Notes**

* The existing `minio_data` volume is reused without modification
* RustFS can read existing MinIO data directly

---

## 2. Update `docker-compose.yml`

Replace the `minio` service:

```yaml
rustfs:
  extends:
    file: compose_databases.yaml
    service: rustfs
  image: rustfs/rustfs:${RUSTFS_VERSION:?RUSTFS_VERSION is required}
  container_name: rustfs
  command: /data --console-address ":9001"
  healthcheck:
    test:
      - "CMD-SHELL"
      - "curl -sf http://localhost:9000/health && curl -sf http://localhost:9001/rustfs/console/health || exit 1"
    interval: 30s
    timeout: 10s
    retries: 5
    start_period: 30s
```

**Required follow-up**

* Replace all `depends_on: minio` with `depends_on: rustfs`

**Health endpoints**

* API: `http://localhost:9000/health`
* Console: `http://localhost:9001/rustfs/console/health`

---

## 3. Update environment variables

In `.env`:

```dotenv
RUSTFS_VERSION=1.0.0-alpha.89
```

Remove:

```dotenv
MINIO_VERSION
```

Keep existing variables:

* `MINIO_ROOT_USER`
* `MINIO_ROOT_PASSWORD`
* `MINIO_PORT`

These are reused via:

* `RUSTFS_ACCESS_KEY`
* `RUSTFS_SECRET_KEY`

---

## 4. Fix volume ownership (required once)

RustFS runs as UID `10001`. Ensure the existing volume matches:

```bash
docker volume inspect suspicious_minio_data
```

Then:

```bash
docker run --rm \
  -v suspicious_minio_data:/data \
  alpine:latest \
  chown -R 10001:10001 /data
```

---

## 5. (Optional) Rename volume

For clarity, you may rename `minio_data` → `rustfs_data`.

### Migration procedure

```bash
docker volume create suspicious_rustfs_data

docker run --rm \
  -v suspicious_minio_data:/from \
  -v suspicious_rustfs_data:/to \
  alpine sh -c "cp -av /from/. /to/"
```

Then update both compose files accordingly.

**Note**: This step is optional and has no functional impact.

---

## 6. Application updates

### Configuration changes

* Update internal hostname:

  * `minio` → `rustfs`

* Ensure endpoint still targets:

  * Port `9000` (S3 API)

### Credentials

* Recreate access keys if required
* Update:

  * `settings.json`
  * `config.json` (email-feeder or related services)

### Compatibility

RustFS is fully S3-compatible, so no application code changes should be required.

---

## Summary

| Area             | Change required         |
| ---------------- | ----------------------- |
| Service name     | `minio` → `rustfs`      |
| Docker image     | Updated                 |
| Environment vars | Prefixed with `RUSTFS_` |
| Volume           | Reused                  |
| Data migration   | None                    |
| App changes      | Hostname update only    |
