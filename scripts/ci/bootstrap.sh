#!/usr/bin/env bash
# Randomized fake-company deploy + full-chain smoke. Local or CI.
# Usage: [SEED=<int>] scripts/ci/bootstrap.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# Fresh checkouts (CI) have no deployment/.env (it is gitignored); seed it
# from the tracked example. Existing local .env is left untouched.
[ -f deployment/.env ] || cp deployment/.env.example deployment/.env

SEED_ARG=""; [ -n "${SEED:-}" ] && SEED_ARG="--seed ${SEED}"
# shellcheck disable=SC2086
python scripts/ci/gen_company.py ${SEED_ARG} >/dev/null

# Load generated identity (DOMAIN, SVC_PREFIX, COMPOSE_PROJECT_NAME, WEBHOOK_SECRET, MINIO_*).
set -a; . deployment/.env; set +a
# Isolated external network per run (compose declares it external).
export NETWORK_NAME="${COMPOSE_PROJECT_NAME}_net"
COMPOSE="docker compose -f deployment/docker-compose.yml -f deployment/compose.ci.yaml --env-file deployment/.env"
export COMPOSE

cleanup() {
  $COMPOSE logs --no-color > ci-stack.log 2>&1 || true
  $COMPOSE down -v --remove-orphans || true
  docker network rm "$NETWORK_NAME" >/dev/null 2>&1 || true
  # Restore the config files the generator rewrote (tracked) + drop runtime.
  git checkout -- Suspicious/settings.json email-feeder/config.json 2>/dev/null || true
  rm -f scripts/ci/.runtime.json
}
trap cleanup EXIT

docker network create "$NETWORK_NAME" >/dev/null 2>&1 || true

$COMPOSE build
$COMPOSE up -d

# Wait (bounded) for the backend to be reachable + DB migrated-ready.
for _ in $(seq 1 60); do
  if $COMPOSE exec -T suspicious python manage.py showmigrations >/dev/null 2>&1; then break; fi
  sleep 5
done

$COMPOSE exec -T suspicious python manage.py migrate --noinput
ADMIN_USER="$(python -c 'import json;print(json.load(open("scripts/ci/.runtime.json"))["admin_user"])')"
ADMIN_PASS="$(python -c 'import json;print(json.load(open("scripts/ci/.runtime.json"))["admin_pass"])')"
$COMPOSE exec -T -e DJANGO_SUPERUSER_PASSWORD="$ADMIN_PASS" suspicious \
  python manage.py createsuperuser --noinput --username "$ADMIN_USER" --email "admin@example.com" || true
$COMPOSE exec -T suspicious python manage.py collectstatic --noinput || true

python scripts/ci/smoke.py
