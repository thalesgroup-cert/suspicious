#!/usr/bin/env bash
# check-secrets.sh — Abort deployment when placeholder secrets remain in .env
#
# Called automatically by `make up` and `make deploy`.
# Exits 0 when clean, exits 1 with a clear message when placeholders found.

set -euo pipefail

ENV_FILE="${1:-.env}"
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
RESET='\033[0m'
BOLD='\033[1m'

if [ ! -f "$ENV_FILE" ]; then
    echo -e "${RED}✗ $ENV_FILE not found. Run 'make init' first.${RESET}" >&2
    exit 1
fi

FORBIDDEN_PATTERNS=(
    "CHANGE_ME"
    "CHANGEME"
    "your_db_password"
    "your_db_root_password"
    "your_minio_password"
    "your.corporate.domain"
)

failures=()
line_number=0

while IFS= read -r line; do
    line_number=$((line_number + 1))
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    [[ -z "${line// }" ]] && continue
    for pattern in "${FORBIDDEN_PATTERNS[@]}"; do
        if echo "$line" | grep -qi "$pattern"; then
            failures+=("  Line $line_number: $line")
            break
        fi
    done
done < "$ENV_FILE"

if [ ${#failures[@]} -gt 0 ]; then
    echo ""
    echo -e "${RED}${BOLD}✗ Deployment blocked — placeholder secrets found in $ENV_FILE${RESET}"
    echo ""
    echo -e "${YELLOW}Change these values before deploying:${RESET}"
    for f in "${failures[@]}"; do
        echo -e "${RED}$f${RESET}"
    done
    echo ""
    echo -e "${YELLOW}Tip: run${RESET} ${BOLD}make install${RESET} ${YELLOW}to set all values interactively.${RESET}"
    echo ""
    exit 1
fi

echo -e "${GREEN}✓ No placeholder secrets found in $ENV_FILE${RESET}"
exit 0