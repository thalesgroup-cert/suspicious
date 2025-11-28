#!/usr/bin/env bash
set -Eeuo pipefail
source ../.env

echo "📦 Running Django migrations..."

docker compose exec "${WEB_CONTAINER}" python manage.py migrate

echo "✅ Migrations complete."
