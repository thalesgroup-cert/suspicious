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
logged out and the Redis cache is dropped.

Before you run it:

- **Queued Celery tasks are discarded** by the Redis recreate (Redis has no
  volume), so migrate when the queue is quiet. Ongoing cases are re-synced by
  `update_ongoing_cases` within about 5 minutes; Cortex jobs in flight are lost
  and restarted by that sweep.
- The Elasticsearch and Cortex containers are required in this path even when
  `case_search` is off (Cortex stores its data in Elasticsearch).
- If the script dies after stopping the app tier, the app stays down. Re-run
  `make db-auth-migrate`: every step is idempotent. If everything is already
  authenticated it prints "already migrated" and exits (`--force` reruns).

The script ends with `make db-auth-check`.

Order of operations: back up `.env` / `.env.data` -> generate secrets -> stop app
tier -> recreate redis, elasticsearch, chromadb, chromadb_proxy -> wait for them
to be healthy -> create ES accounts -> start app tier -> verify.

### Rollback

Before changing anything the script copies `.env` and `.env.data` (if present)
to `<file>.pre-db-auth.<epoch>`. To roll back, restore those copies **and** check
out the previous release (older compose files do not load `.env.data`), then
`docker compose up -d --force-recreate` the data tier. Redis held only
cache/queue data; Elasticsearch and Chroma volumes are untouched.

### Rotating a secret

All commands run from `deployment/` after editing the value.

| Secret | Steps |
|---|---|
| Redis broker | `docker compose --env-file .env up -d --force-recreate --no-deps redis_broker suspicious suspicious_celery suspicious_celery_beat` (about 30 s, users logged out) |
| Redis cache | same with `redis_cache` instead of `redis_broker` |
| ES app / Cortex users | `bash scripts/es-security-bootstrap.sh`, then `up -d --force-recreate --no-deps suspicious suspicious_celery cortex` |
| `ELASTIC_PASSWORD` | Send the change through the security API with a curl config on stdin, so neither password appears in argv: `printf 'user = "elastic:OLD"\ndata = "{\"password\":\"NEW\"}"\n' \| docker compose exec -T elasticsearch curl -sS -K - -X POST -H 'Content-Type: application/json' http://localhost:9200/_security/user/elastic/_password` (run it with history disabled). Then update `.env.data` and `up -d --force-recreate --no-deps elasticsearch` (its healthcheck reads the container's `$ELASTIC_PASSWORD`) |
| `CHROMA_TOKEN` | recreate `chromadb_proxy suspicious suspicious_celery` |
