#!/usr/bin/env bash
# deploy.sh — Zero-downtime rolling deploy for Suspicious.
#
# Order of operations:
#   1. Pull latest images (no downtime — just downloads)
#   2. Run database migrations (forward-compatible migrations first)
#   3. Restart suspicious (rolling — healthcheck gates the cutover)
#   4. Restart suspicious_cron (simple restart, no web traffic)
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

# ── 2. Pull images ────────────────────────────────────────────────────────
step "Pulling latest images"
$COMPOSE pull suspicious suspicious_ui feeder
ok "Images pulled"

# ── 3. Migrations (before web restart — forward-compatible required) ──────
step "Running database migrations"
# Run against the CURRENTLY running container (old version handles old schema)
$COMPOSE exec -T "${WEB_CONTAINER}" python manage.py migrate --no-input
ok "Migrations applied"

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

# ── 6. Restart cron worker ────────────────────────────────────────────────
step "Restarting suspicious_cron"
$COMPOSE up -d --no-deps suspicious_cron
ok "suspicious_cron restarted"

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