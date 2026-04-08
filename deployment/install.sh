#!/usr/bin/env bash
# install.sh — Suspicious platform bootstrapper
#
# Designed to be run directly:
#   bash install.sh
#
# Or piped from curl (one-command install):
#   curl -fsSL https://raw.githubusercontent.com/thalesgroup-cert/suspicious/main/install.sh | bash
#
# What this script does:
#   1. Checks system requirements (Docker, Python 3.10+, git, curl)
#   2. Clones the repository (or uses the current directory if already inside it)
#   3. Installs Python TUI dependencies (questionary, rich)
#   4. Launches install.py — the interactive wizard
#
# Nothing is deployed until install.py finishes and the user confirms.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

REPO_URL="https://github.com/thalesgroup-cert/suspicious"
REPO_DIR="suspicious-deploy"
MIN_PYTHON_MINOR=10

banner() {
    echo ""
    echo -e "${CYAN}${BOLD}"
    echo "  ███████╗██╗   ██╗███████╗██████╗ ██╗ ██████╗██╗ ██████╗ ██╗   ██╗███████╗"
    echo "  ██╔════╝██║   ██║██╔════╝██╔══██╗██║██╔════╝██║██╔═══██╗██║   ██║██╔════╝"
    echo "  ███████╗██║   ██║███████╗██████╔╝██║██║     ██║██║   ██║██║   ██║███████╗"
    echo "  ╚════██║██║   ██║╚════██║██╔═══╝ ██║██║     ██║██║   ██║██║   ██║╚════██║"
    echo "  ███████║╚██████╔╝███████║██║     ██║╚██████╗██║╚██████╔╝╚██████╔╝███████║"
    echo "  ╚══════╝ ╚═════╝ ╚══════╝╚═╝     ╚═╝ ╚═════╝╚═╝ ╚═════╝  ╚═════╝ ╚══════╝"
    echo -e "${RESET}"
    echo -e "${BOLD}  Phishing analysis platform — interactive installer${RESET}"
    echo ""
}

check_binary() {
    local name="$1"
    local install_hint="$2"
    if ! command -v "$name" &>/dev/null; then
        echo -e "${RED}✗ Required: ${BOLD}$name${RESET}${RED} — $install_hint${RESET}"
        return 1
    fi
    echo -e "${GREEN}✓ $name$(${name} --version 2>/dev/null | head -1 | sed 's/^/ /')${RESET}"
}

check_docker_compose() {
    if ! docker compose version &>/dev/null; then
        echo -e "${RED}✗ Docker Compose v2 not available (docker compose subcommand required)${RESET}"
        echo "  Upgrade Docker Desktop or install the compose plugin:"
        echo "  https://docs.docker.com/compose/install/"
        exit 1
    fi
    echo -e "${GREEN}✓ docker compose $(docker compose version --short)${RESET}"
}

check_python() {
    local py_cmd=""
    for cmd in python3 python; do
        if command -v "$cmd" &>/dev/null; then
            local ver
            ver=$("$cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null)
            local minor
            minor=$(echo "$ver" | cut -d. -f2)
            if [ "${minor:-0}" -ge "$MIN_PYTHON_MINOR" ]; then
                py_cmd="$cmd"
                echo -e "${GREEN}✓ Python $ver${RESET}" >&2
                break
            fi
        fi
    done
    if [ -z "$py_cmd" ]; then
        echo -e "${RED}✗ Python 3.${MIN_PYTHON_MINOR}+ required — https://python.org/downloads${RESET}" >&2
        exit 1
    fi
    echo "$py_cmd"
}

banner

echo -e "${BOLD}Checking requirements...${RESET}"
check_binary "git"   "https://git-scm.com"
check_binary "curl"  "apt install curl / brew install curl"
check_docker_compose
PY=$(check_python)

# ── Clone repo if not already inside it ──────────────────────────────────
if [ ! -f "docker-compose.yml" ] && [ ! -f "Makefile" ]; then
    echo ""
    echo -e "${YELLOW}Cloning Suspicious repository...${RESET}"
    if [ -d "$REPO_DIR" ]; then
        echo "Directory $REPO_DIR already exists — pulling latest changes."
        cd "$REPO_DIR" && git pull
    else
        git clone "$REPO_URL" "$REPO_DIR"
        cd "$REPO_DIR"
    fi
fi

# ── Install Python TUI dependencies ──────────────────────────────────────
echo ""
echo -e "${YELLOW}Installing installer dependencies...${RESET}"
#"$PY" -m pip install --quiet --upgrade questionary rich

# ── Launch interactive wizard ─────────────────────────────────────────────
echo ""
"$PY" install.py