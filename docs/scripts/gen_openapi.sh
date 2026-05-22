#!/usr/bin/env bash
# Generate the OpenAPI schema into docs/reference/openapi.yaml.
#
# Requires the backend's Python environment (Django + drf-spectacular).
# Uses the committed CI config fixture so no real settings.json is needed;
# the backend falls back to SQLite when /app/log is absent.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="${REPO_ROOT}/docs/reference/openapi.yaml"
PY="$(command -v python3 || command -v python)"
STUBS_DIR="${REPO_ROOT}/docs/scripts/_stubs"

cd "${REPO_ROOT}/Suspicious/Suspicious"
SUSPICIOUS_CONFIG_PATH="${REPO_ROOT}/Suspicious/settings.ci.json" \
  PYTHONPATH="${STUBS_DIR}${PYTHONPATH:+:${PYTHONPATH}}" \
  "${PY}" manage.py spectacular \
    --settings=suspicious.settings \
    --file "${OUT}"

echo "Wrote ${OUT}"
