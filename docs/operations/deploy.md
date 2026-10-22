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

## Network segmentation

The stack no longer runs on one flat network. `suspicious_network` (created by
`make network`) stays the shared network for the reverse proxy, the UI, the
feeder, Vault and integrations such as TheHive, MISP or monitoring. Three
networks managed by Compose sit behind it, so a compromised front-end service
cannot connect to a database:

| Network | Members | Reachable by |
|---|---|---|
| `data` (internal, no outbound traffic) | MariaDB (and replica), Redis broker, Redis cache, Chroma proxy | Django, Celery worker, Celery beat |
| `storage` | RustFS | Django, Celery worker, feeder |
| `cortex` | Cortex, Elasticsearch | Django, Celery worker |

The Chroma server itself sits on its own internal link behind the proxy. The UI,
the reverse proxy and Vault are not on any of the three networks; the feeder
reaches only the Django API and RustFS; Cortex reaches only Elasticsearch and
the Django webhook. Cortex still needs the Docker socket to start analyzers.

`make network-check` verifies that every service is on exactly the networks it
needs and that the paths it needs work (Django and Celery reach every data
service, the feeder reaches Django and RustFS, Cortex reaches Elasticsearch and
the webhook, and the feeder cannot resolve Redis or MariaDB). `make deploy`
runs it at the end.

### Upgrading an existing deployment

`make deploy` handles it. As the last step it recreates MariaDB and RustFS so
they join their own networks and leave the shared one. Compose only recreates a
service whose configuration changed, so this is a no-op on an up-to-date stack
and a single restart of MariaDB and RustFS (a few seconds of database errors,
once) on the first run. Run it in a quiet period. Tools that connected to
MariaDB, Elasticsearch or Redis through `suspicious_network` from outside the
stack (a backup container, a monitoring exporter) must be attached to the
network they need or use `docker compose exec`.

## Docker socket and container hardening

Neither Traefik nor Cortex mounts the host Docker socket any more. Each reaches
the daemon through its own `tecnativa/docker-socket-proxy` container on a private
network that only the two of them share:

| Proxy | Allowed | Used by |
|---|---|---|
| `docker_proxy_traefik` | listing containers and events, read only (`POST=0`) | Traefik's Docker provider |
| `docker_proxy_cortex` | containers, images and daemon info, with writes | Cortex's Docker job runner |

The Traefik proxy removes the host takeover path: Traefik can no longer create
or start containers. The Cortex proxy is a narrower surface, not a complete
fix. Cortex has to create containers to run analyzers, and the proxy filters by
path and method, not by request body, so a compromised Cortex could still ask
for a privileged container. Treat Cortex as high risk: run it on a host where
the Docker daemon is rootless, or run analyzers on a dedicated host, if the
platform handles hostile content from untrusted reporters.

**Required when you upgrade:** if your `traefik.yaml` defines its own Docker
provider, set `providers.docker.endpoint: tcp://docker_proxy_traefik:2375`.
A static file overrides the flag in the compose file, and `make deploy` stops
with a message if the endpoint is missing (`scripts/check-traefik-provider.sh`).
Cortex needs no change: the compose file passes `docker.host` as a Java option,
and `DOCKER_SOCK_GID` is no longer used by Cortex.

The Django, Celery, beat and feeder containers also run with every Linux
capability dropped and `no-new-privileges`. The UI and Cortex start as root and
then drop to their own user, so they keep only `CHOWN`, `DAC_OVERRIDE`, `SETGID`
and `SETUID`. Vault is unchanged.
