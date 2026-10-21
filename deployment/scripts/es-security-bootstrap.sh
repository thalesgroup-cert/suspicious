#!/usr/bin/env bash
# Create/refresh the Elasticsearch roles and users Suspicious and Cortex use.
# Idempotent: PUT replaces the user, so re-running also applies a rotated
# password from .env. Needs the elasticsearch container up (ELASTIC_PASSWORD is
# read from .env.data, the service accounts from .env).
set -euo pipefail
cd "$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="${ENV_FILE:-.env}"
DATA_ENV_FILE="${DATA_ENV_FILE:-.env.data}"
COMPOSE="${COMPOSE:-docker compose --env-file $ENV_FILE}"
set -a; . "$(realpath "$ENV_FILE")"; . "$(realpath "$DATA_ENV_FILE")"; set +a
for v in ELASTIC_PASSWORD ES_SUSPICIOUS_USER ES_SUSPICIOUS_PASSWORD ES_CORTEX_USER ES_CORTEX_PASSWORD; do
  [[ "${!v:-}" =~ ^[A-Za-z0-9_.-]+$ ]] || { echo "ERROR: $v is empty or has characters outside [A-Za-z0-9_.-]" >&2; exit 1; }
done

es() {  # es METHOD PATH [JSON]
  $COMPOSE exec -T -e ES_AUTH="elastic:${ELASTIC_PASSWORD}" elasticsearch \
    sh -c 'curl -sf -u "$ES_AUTH" -X "$0" -H "Content-Type: application/json" "http://localhost:9200$1" ${2:+-d "$2"}' \
    "$1" "$2" "${3:-}" >/dev/null || { echo "ERROR: Elasticsearch call failed: $1 $2" >&2; exit 1; }
}

for _ in $(seq 1 60); do
  $COMPOSE exec -T -e ES_AUTH="elastic:${ELASTIC_PASSWORD}" elasticsearch \
    sh -c 'curl -sf -u "$ES_AUTH" http://localhost:9200/_cluster/health' >/dev/null 2>&1 && break
  sleep 3
done

es PUT /_security/role/suspicious_app '{"cluster":["monitor"],"indices":[{"names":["suspicious-*"],"privileges":["create_index","index","write","read","view_index_metadata"]}]}'
es PUT /_security/role/cortex_app    '{"cluster":["monitor","manage_index_templates"],"indices":[{"names":["cortex*"],"privileges":["all"]}]}'
es PUT "/_security/user/${ES_SUSPICIOUS_USER}" "{\"password\":\"${ES_SUSPICIOUS_PASSWORD}\",\"roles\":[\"suspicious_app\"]}"
es PUT "/_security/user/${ES_CORTEX_USER}"     "{\"password\":\"${ES_CORTEX_PASSWORD}\",\"roles\":[\"cortex_app\"]}"
echo "Elasticsearch roles and users ready"
