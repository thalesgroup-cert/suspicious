#!/usr/bin/env bash
# check-updates.sh — Compare running Suspicious image digest against GHCR.
#
# Usage: ./scripts/check-updates.sh
# Prints a table of running vs available versions.
# Exits 0 if up-to-date, 1 if updates are available.

set -euo pipefail
source .env

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

IMAGE="ghcr.io/thalesgroup-cert/suspicious"
SERVICES=("suspicious" "suspicious_ui")

updates_available=0

echo ""
echo -e "${BOLD}Suspicious — update check${RESET}"
echo -e "${CYAN}─────────────────────────────────────────────────────${RESET}"
printf "  %-22s %-20s %-20s %s\n" "Service" "Running" "Registry" "Status"
echo -e "${CYAN}─────────────────────────────────────────────────────${RESET}"

for svc in "${SERVICES[@]}"; do
    container=$(docker compose ps -q "$svc" 2>/dev/null || true)

    if [ -z "$container" ]; then
        printf "  %-22s %-20s %-20s %s\n" "$svc" "not running" "—" "⚠ stopped"
        continue
    fi

    running_digest=$(docker inspect --format='{{index .RepoDigests 0}}' "$container" 2>/dev/null \
        | sed 's/.*@//' | cut -c1-12 || echo "unknown")

    # Pull manifest without downloading (uses docker manifest inspect if available)
    registry_digest=$(docker manifest inspect "${IMAGE}:${SUSPICIOUS_VERSION}" 2>/dev/null \
        | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(d.get('config', {}).get('digest', d.get('schemaVersion', '?'))[:12])
except Exception:
    print('unknown')
" 2>/dev/null || echo "unknown")

    if [ "$running_digest" = "$registry_digest" ] || [ "$registry_digest" = "unknown" ]; then
        status="${GREEN}✓ up-to-date${RESET}"
    else
        status="${YELLOW}↑ update available${RESET}"
        updates_available=1
    fi

    printf "  %-22s %-20s %-20s " "$svc" "$running_digest" "$registry_digest"
    echo -e "$status"
done

echo ""

if [ "$updates_available" -eq 1 ]; then
    echo -e "${YELLOW}Updates available. Run:${RESET} ${BOLD}make upgrade${RESET}"
    exit 1
else
    echo -e "${GREEN}Everything is up-to-date.${RESET}"
    exit 0
fi