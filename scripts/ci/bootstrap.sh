#!/usr/bin/env bash
# Randomized fake-company deploy + full-chain smoke. Local or CI.
# Usage: [SEED=<int>] scripts/ci/bootstrap.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# Fresh checkouts (CI) lack the gitignored config files; seed them from the
# tracked templates. Existing local files are left untouched. Back up .env so
# a local run can restore it (git checkout can't — it's gitignored).
[ -f deployment/.env ] || cp deployment/.env.example deployment/.env
[ -f Suspicious/settings.json ] || cp Suspicious/settings.ci.json Suspicious/settings.json
[ -f email-feeder/config.json ] || cp docs/getting-started/examples/email-feeder-config.example.json email-feeder/config.json
cp deployment/.env deployment/.env.ci.bak 2>/dev/null || true

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
  { mv deployment/.env.ci.bak deployment/.env 2>/dev/null || rm -f deployment/.env; } || true
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

# Regression suites guarding this session's fixes (ledger + preview).
$COMPOSE exec -T suspicious python manage.py test \
  tasp cortex_job \
  mail_feeder.tests.test_fetch_eml_bytes mail_feeder.tests.test_preview_jobs \
  api.tests.test_mail_preview_view

python scripts/ci/smoke.py
