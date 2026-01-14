#!/usr/bin/env bash
set -Eeuo pipefail
source .env

# Simple log function
log() {
    echo "[create-superuser] $1"
}

log "Using container name: $WEB_CONTAINER"

# Ensure the container is running
if ! docker compose ps --status running | grep -q "$WEB_CONTAINER"; then
    log "Error: Suspicious container '$WEB_CONTAINER' is not running."
    log "Start the stack first:"
    echo "  docker compose up -d"
    exit 1
fi

# Create Suspicious superuser interactively
log "Launching Suspicious superuser creation..."
docker compose exec "$WEB_CONTAINER" python manage.py createsuperuser

log "Superuser creation completed successfully."
