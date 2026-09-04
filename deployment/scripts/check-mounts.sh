#!/usr/bin/env bash
set -Eeuo pipefail
source .env

# Guards against Docker's bind-mount footgun: when the *host* side of a
# `- "host:container"` mount does not exist at container-create time, Docker
# silently creates it — always as a **root-owned directory**. For a file mount
# (settings.json, config.json) the container then sees a directory where it
# wants a file and dies with a confusing error far from the real cause; for a
# log dir it gets a directory the non-root app user can't write to.
#
# Runs before every `make up`. Scope is deliberately the two gitignored config
# files and the app log dirs — the paths that actually keep getting clobbered.
# Certs / Cortex config are `make init`'s job and have their own handling.
# This never fabricates config content: a missing settings.json is a hard stop.

fail=0

# host path -> how to fix it if missing
REQUIRED_FILES=(
    "${SUSPICIOUS_PATH}/settings.json|make init  (seeds it from settings-sample.json), then edit"
    "${FEEDER_PATH}/config.json|make init  (seeds it from config-sample.json), then edit"
)

REQUIRED_DIRS=(
    "${SUSPICIOUS_PATH}/logs"
    "${FEEDER_PATH}/logs"
    "${TRAEFIK_PATH}/logs"
)

for entry in "${REQUIRED_FILES[@]}"; do
    path="${entry%%|*}"; hint="${entry#*|}"
    [ -f "$path" ] && continue
    if [ -d "$path" ]; then
        if rmdir "$path" 2>/dev/null; then
            echo "→ removed stray empty directory (Docker bind-mount artifact): $path"
        else
            echo "ERROR: $path is a non-empty directory but a file is expected — inspect and remove it by hand." >&2
            fail=1; continue
        fi
    fi
    echo "ERROR: missing required file: $path" >&2
    echo "       fix: $hint" >&2
    fail=1
done

for path in "${REQUIRED_DIRS[@]}"; do
    if [ -e "$path" ] && [ ! -d "$path" ]; then
        echo "ERROR: $path exists but is not a directory (expected a log dir)." >&2
        fail=1; continue
    fi
    [ -d "$path" ] || { mkdir -p "$path"; echo "→ created log directory: $path"; }
done

if [ "$fail" -ne 0 ]; then
    echo >&2
    echo "check-mounts: refusing to start — run 'make init' if this is a fresh setup." >&2
    exit 1
fi

echo "→ bind-mount paths OK"
