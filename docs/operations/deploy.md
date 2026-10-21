# Deploy & Rollback

Updates are applied with a zero-downtime rolling update from `deployment/`:

```bash
make deploy   # pull new images → run migrations → restart services in order
```

Individual steps are also available: `make migrate`, `make collectstatic`,
`make build`. Check health afterwards with `make status` and tail logs with
`make logs s=<service>`.

To roll back, redeploy the previous image tags (set in `deployment/.env`) and
run `make deploy` again.

## Authenticated data services

Redis, Elasticsearch and ChromaDB require credentials (see
[Internal service authentication](../../CONFIG.md#internal-service-authentication)).
New installs get them from `make init`.

### Upgrading an existing deployment (one time)

`make deploy` refuses to run until the data services enforce authentication.
Back up first (`make backup-db`), then:

```bash
make db-auth-migrate
```

Maintenance window of about 1-2 minutes: the app tier stops (Celery gets a warm
shutdown), the data tier restarts with authentication, the Elasticsearch service
accounts are created, then the app tier starts with credentials. Users are
logged out and the Redis cache is dropped. The script is safe to re-run from the
top and ends with `make db-auth-check`.

Order of operations: generate secrets -> stop app tier -> recreate redis,
elasticsearch, chromadb, chromadb_proxy -> wait for Elasticsearch -> create ES
accounts -> start app tier -> verify.

### Rollback

Restore the previous `.env`, check out the previous release and
`docker compose up -d --force-recreate` the data tier. Redis held only
cache/queue data; Elasticsearch and Chroma volumes are untouched.

### Rotating a secret

All commands run from `deployment/` after editing the value.

| Secret | Steps |
|---|---|
| Redis broker | `docker compose --env-file .env up -d --force-recreate --no-deps redis_broker suspicious suspicious_celery suspicious_celery_beat` (about 30 s, users logged out) |
| Redis cache | same with `redis_cache` instead of `redis_broker` |
| ES app / Cortex users | `bash scripts/es-security-bootstrap.sh`, then `up -d --force-recreate --no-deps suspicious suspicious_celery cortex` |
| `ELASTIC_PASSWORD` | `POST /_security/user/elastic/_password` with the old value, then update `.env.data` (the variable only matters until the first API change) |
| `CHROMA_TOKEN` | recreate `chromadb_proxy suspicious suspicious_celery` |
