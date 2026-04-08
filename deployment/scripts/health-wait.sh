#!/usr/bin/env bash
# health-wait.sh — Wait for a container to reach "healthy" status.
#
# Usage: ./health-wait.sh <container_name> [timeout_seconds]
#
# Used by deploy.sh to ensure the new container is healthy before
# the rolling restart removes the old one.

set -euo pipefail

CONTAINER="${1:?Usage: health-wait.sh <container_name> [timeout_seconds]}"
TIMEOUT="${2:-120}"
INTERVAL=5

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
RESET='\033[0m'

echo -e "${YELLOW}⏳ Waiting for $CONTAINER to become healthy (timeout: ${TIMEOUT}s)...${RESET}"

elapsed=0
while [ "$elapsed" -lt "$TIMEOUT" ]; do
    status=$(docker inspect --format='{{.State.Health.Status}}' "$CONTAINER" 2>/dev/null || echo "missing")

    case "$status" in
        healthy)
            echo -e "${GREEN}✓ $CONTAINER is healthy (${elapsed}s)${RESET}"
            exit 0
            ;;
        unhealthy)
            echo -e "${RED}✗ $CONTAINER became unhealthy. Check logs:${RESET}"
            echo "  docker logs $CONTAINER --tail 50"
            exit 1
            ;;
        missing)
            echo -e "${RED}✗ Container $CONTAINER not found.${RESET}"
            exit 1
            ;;
        *)
            printf "  Status: %-12s elapsed: %ds\r" "$status" "$elapsed"
            ;;
    esac

    sleep "$INTERVAL"
    elapsed=$((elapsed + INTERVAL))
done

echo -e "${RED}✗ Timeout after ${TIMEOUT}s — $CONTAINER never became healthy.${RESET}"
echo "  docker logs $CONTAINER --tail 100"
exit 1