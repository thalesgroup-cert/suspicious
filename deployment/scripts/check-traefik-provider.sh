#!/usr/bin/env bash
# Traefik has no Docker socket and no Docker proxy. A traefik.yaml that enables the
# Docker provider would try /var/run/docker.sock and fail, so stop before deploying.
set -euo pipefail
cd "$(cd "$(dirname "$0")/.." && pwd)"
set -a; . "${ENV_FILE:-.env}"; set +a
f="${TRAEFIK_PATH:-../traefik}/traefik.yaml"
[ -f "$f" ] || exit 0
if grep -qE '^[[:space:]]*docker:' "$f"; then
  echo "ERROR: $f enables the Docker provider, but Traefik has no Docker access." >&2
  echo "       Remove providers.docker and declare routes in ${TRAEFIK_PATH:-../traefik}/dynamic (file provider)." >&2
  exit 1
fi
