#!/usr/bin/env bash
# One-time upgrade of an existing deployment to authenticated data services.
# Maintenance window ~1-2 min: Redis cannot accept clients with credentials
# before it enforces them, so the app tier stops, the data tier restarts with
# auth, and the app tier starts with credentials.
# Safe to re-run from the top (generator, recreate and bootstrap are idempotent).
# Rollback: restore the previous .env, check out the previous release and
# `docker compose up -d --force-recreate` the data tier. Redis held only
# cache/queue data; Elasticsearch and Chroma volumes are untouched.
set -euo pipefail
cd "$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="${ENV_FILE:-.env}"; COMPOSE="${COMPOSE:-docker compose --env-file $ENV_FILE}"
bash scripts/gen-service-secrets.sh "$ENV_FILE"   # also creates .env.data (mode 600)
set -a; . "./$ENV_FILE"; set +a
if [ "${ASSUME_YES:-0}" != 1 ]; then
  read -r -p "Stops the app for ~2 min, drops sessions and the Redis cache. Back up first (make backup-db). Continue? [y/N] " a
  [[ "$a" =~ ^[Yy]$ ]] || exit 1
fi
$COMPOSE pull suspicious feeder || $COMPOSE build suspicious feeder          # new image must know the credentials
$COMPOSE stop -t 120 suspicious_celery                                       # warm shutdown: running tasks finish
$COMPOSE stop suspicious_celery_beat suspicious feeder cortex
$COMPOSE up -d --force-recreate --no-deps redis_broker redis_cache elasticsearch chromadb chromadb_proxy
bash scripts/health-wait.sh "${SVC_PREFIX:-}elasticsearch" 240
bash scripts/es-security-bootstrap.sh
$COMPOSE up -d --no-deps suspicious suspicious_celery suspicious_celery_beat feeder cortex
bash scripts/health-wait.sh "${WEB_CONTAINER:-suspicious}" 180
bash scripts/db-auth-check.sh
