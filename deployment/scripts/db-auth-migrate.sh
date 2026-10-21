#!/usr/bin/env bash
# One-time upgrade of an existing deployment to authenticated data services.
#   usage: db-auth-migrate.sh [--force]     (ASSUME_YES=1 skips the prompt)
#
# Maintenance window ~1-2 min: Redis cannot accept clients with credentials
# before it enforces them, so the app tier stops, the data tier restarts with
# auth, and the app tier starts with credentials.
#  - Queued Celery tasks are discarded (redis has no volume); migrate while the
#    queue is quiet. Ongoing cases are re-synced by update_ongoing_cases within
#    ~5 min; Cortex jobs in flight are lost and restarted by that sweep.
#  - Elasticsearch and Cortex containers are required even if case_search is off.
#  - If the script dies after stopping the app tier, the app stays down:
#    re-run `make db-auth-migrate` (every step is idempotent).
# Rollback: restore .env / .env.data from <file>.pre-db-auth.<epoch> (copied here
# before anything changes), AND check out the previous release (older compose
# files have no env_file .env.data), then `docker compose up -d --force-recreate`
# the data tier. Redis held only cache/queue data; ES and Chroma volumes are untouched.
set -euo pipefail
cd "$(cd "$(dirname "$0")/.." && pwd)"
FORCE=0; [ "${1:-}" = "--force" ] && FORCE=1
ENV_FILE="$(realpath "${ENV_FILE:-.env}")"
DATA_ENV_FILE="$(realpath "${DATA_ENV_FILE:-$(dirname "$ENV_FILE")/.env.data}")"
COMPOSE="${COMPOSE:-docker compose --env-file $ENV_FILE}"
export ENV_FILE DATA_ENV_FILE COMPOSE

if [ "$FORCE" != 1 ] && bash scripts/db-auth-check.sh >/dev/null 2>&1; then
  echo "Already migrated: every data service enforces authentication (use --force to rerun)."
  exit 0
fi
if [ "${ASSUME_YES:-0}" != 1 ]; then
  read -r -p "Stops the app for ~2 min, drops sessions, the Redis cache and QUEUED tasks (migrate while the queue is quiet; in-flight Cortex jobs are restarted by the 5-min sweep). Back up first (make backup-db). Continue? [y/N] " a
  [[ "$a" =~ ^[Yy]$ ]] || exit 1
fi
ts=$(date +%s)
for f in "$ENV_FILE" "$DATA_ENV_FILE"; do
  if [ -f "$f" ]; then cp -p "$f" "$f.pre-db-auth.$ts"; echo "Backed up $f -> $f.pre-db-auth.$ts"; fi
done
bash scripts/gen-service-secrets.sh "$ENV_FILE" "$DATA_ENV_FILE"   # also creates .env.data (mode 600)
set -a; . "$ENV_FILE"; . "$DATA_ENV_FILE"; set +a
P="${SVC_PREFIX:-}"

$COMPOSE pull suspicious feeder || $COMPOSE build suspicious feeder          # new image must know the credentials
$COMPOSE stop -t 120 suspicious_celery                                       # warm shutdown: running tasks finish
$COMPOSE stop suspicious_celery_beat suspicious feeder cortex
$COMPOSE up -d --force-recreate --no-deps redis_broker redis_cache elasticsearch chromadb chromadb_proxy
for c in redis_broker redis_cache elasticsearch chromadb_proxy; do bash scripts/health-wait.sh "${P}$c" 240; done
bash scripts/es-security-bootstrap.sh
$COMPOSE up -d --no-deps suspicious suspicious_celery suspicious_celery_beat feeder cortex
bash scripts/health-wait.sh "${P}suspicious" 180
bash scripts/db-auth-check.sh
