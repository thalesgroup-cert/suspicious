#!/usr/bin/env bash
set -Eeuo pipefail
source .env

TARGET_DIR="$1"

if [[ -z "$TARGET_DIR" ]]; then
    echo "Usage: wait-empty.sh <remote_path>"
    exit 1
fi

echo "⏳ Waiting for directory to be empty: $TARGET_DIR ..."

while docker compose exec -T "$WEB_CONTAINER" sh -c "ls -A $TARGET_DIR" | grep -q .; do
    echo "Still not empty... waiting 5s"
    sleep 5
done

echo "✅ Directory is empty."
