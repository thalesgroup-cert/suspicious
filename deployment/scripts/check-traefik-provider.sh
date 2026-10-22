#!/usr/bin/env bash
# Traefik no longer mounts the Docker socket: it reads container labels through
# docker_proxy_traefik. A traefik.yaml with its own docker provider overrides the
# --providers.docker.endpoint flag in compose, so it must point at the proxy too.
set -euo pipefail
cd "$(cd "$(dirname "$0")/.." && pwd)"
set -a; . "${ENV_FILE:-.env}"; set +a
f="${TRAEFIK_PATH:-../traefik}/traefik.yaml"
[ -f "$f" ] || exit 0
grep -qE '^[[:space:]]*docker:' "$f" || exit 0
if ! grep -qE 'endpoint:[[:space:]]*"?tcp://docker_proxy_traefik:2375"?' "$f"; then
  echo "ERROR: $f enables the Docker provider without 'endpoint: tcp://docker_proxy_traefik:2375'." >&2
  echo "       Traefik no longer has the Docker socket; add that endpoint under providers.docker." >&2
  exit 1
fi
