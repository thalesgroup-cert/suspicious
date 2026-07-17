#!/usr/bin/env bash
# deploy.sh — Zero-downtime rolling deploy for Suspicious.
#
# Order of operations:
#   1. Pull latest images (no downtime — just downloads)
#   2. Run database migrations (forward-compatible migrations first)
#   3. Restart suspicious (rolling — healthcheck gates the cutover)
#   4. Restart suspicious_celery (Celery worker + Beat, no web traffic)
#   5. Restart feeder (simple restart)
#   6. Restart suspicious_ui (static files, near-instant)
#
# Services that are NOT restarted here (no code changes):
#   - db_suspicious, elasticsearch, rustfs, chromadb, traefik
#   Use `docker compose restart <service>` if you need to restart them manually.

set -euo pipefail
source .env

COMPOSE="docker compose --env-file .env"
SCRIPTS="./scripts"
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
RESET='\033[0m'

step() { echo -e "\n${YELLOW}${BOLD}▶ $1${RESET}"; }
ok()   { echo -e "${GREEN}✓ $1${RESET}"; }

# ── 1. Pre-flight checks ──────────────────────────────────────────────────
step "Pre-flight checks"
bash "${SCRIPTS}/check-secrets.sh" .env
bash "${SCRIPTS}/check-network.sh"
ok "Pre-flight passed"

# ── 1b. Unseal Vault (before any container reads secrets from it) ─────────
step "Unsealing Vault"
bash "${SCRIPTS}/unseal-vault.sh"
ok "Vault unseal checked"

# ── 2. Pull images (build from source any the registry doesn't serve) ─────
# A missing/forbidden registry tag (e.g. a service whose image isn't published)
# must not abort the deploy: pull each service independently and build from
# source the ones that fail, so a source-based stack deploys the same way.
step "Pulling latest images"
to_build=""
for svc in suspicious suspicious_ui feeder; do
  if $COMPOSE pull "$svc"; then
    ok "pulled $svc"
  else
    echo -e "${YELLOW}  pull failed for ${svc} — will build from source${RESET}"
    to_build="${to_build} ${svc}"
  fi
done
if [ -n "${to_build}" ]; then
  step "Building from source:${to_build}"
  $COMPOSE build ${to_build}
fi
ok "Images ready"

# ── 3. Migrations (before web restart — forward-compatible required) ──────
step "Running database migrations"
# Run against the CURRENTLY running container (old version handles old schema)
$COMPOSE exec -T "${WEB_CONTAINER}" python manage.py migrate --no-input
ok "Migrations applied"

# ── 3b. Seed runtime config (idempotent) ─────────────────────────────────
step "Seeding runtime config"
$COMPOSE exec -T "${WEB_CONTAINER}" python manage.py seed_config
ok "Runtime config seeded"

# ── 4. Collect static files ───────────────────────────────────────────────
step "Collecting static files"
$COMPOSE exec -T "${WEB_CONTAINER}" python manage.py collectstatic --no-input --clear
ok "Static files collected"

# ── 5. Rolling restart: suspicious ───────────────────────────────────────
# --no-deps: don't restart dependencies (db, cortex, etc.)
# The old container stays alive until the new one passes its healthcheck.
step "Rolling restart: suspicious (web)"
$COMPOSE up -d --no-deps suspicious
bash "${SCRIPTS}/health-wait.sh" suspicious 120
ok "suspicious restarted"

# ── 6. Restart Celery worker + Beat ──────────────────────────────────────
step "Restarting suspicious_celery"
$COMPOSE up -d --no-deps suspicious_celery
ok "suspicious_celery restarted"

# ── 7. Restart feeder ────────────────────────────────────────────────────
step "Restarting feeder"
$COMPOSE up -d --no-deps feeder
ok "feeder restarted"

# ── 8. Restart UI ────────────────────────────────────────────────────────
step "Restarting suspicious_ui"
$COMPOSE up -d --no-deps suspicious_ui
ok "suspicious_ui restarted"

# ── Done ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}✓ Deploy complete.${RESET}"
echo ""
$COMPOSE ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"