#!/usr/bin/env bash
# Create/refresh the Elasticsearch roles and users Suspicious and Cortex use.
# Idempotent: PUT replaces the user, so re-running also applies a rotated
# password from .env. Needs the elasticsearch container up (ELASTIC_PASSWORD is
# read from .env.data, the service accounts from .env).
set -euo pipefail
cd "$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="$(realpath "${ENV_FILE:-.env}")"
DATA_ENV_FILE="$(realpath "${DATA_ENV_FILE:-$(dirname "$ENV_FILE")/.env.data}")"
COMPOSE="${COMPOSE:-docker compose --env-file $ENV_FILE}"
set -a; . "$ENV_FILE"; . "$DATA_ENV_FILE"; set +a
for v in ELASTIC_PASSWORD ES_SUSPICIOUS_USER ES_SUSPICIOUS_PASSWORD ES_CORTEX_USER ES_CORTEX_PASSWORD; do
  [[ "${!v:-}" =~ ^[A-Za-z0-9_.-]+$ ]] || { echo "ERROR: $v is empty or has characters outside [A-Za-z0-9_.-]" >&2; exit 1; }
done

export ES_AUTH="elastic:${ELASTIC_PASSWORD}"

# No secret appears in any argv, on the host or in the container: the
# credential is an inherited env var that curl reads from a config on stdin
# (printf is a builtin), and the JSON body arrives on the container's stdin.
CURL_SH='exec 3<&0; printf "user = \"%s\"\n" "$ES_AUTH" |
  curl -sS -K - -w "\n%{http_code}" -X "$0" -H "Content-Type: application/json" \
    ${2:+--data-binary @/dev/fd/3} "http://localhost:9200$1"'

es() {  # es METHOD PATH [JSON]  (prints the response body on failure)
  local out code
  out=$(printf '%s' "${3:-}" | $COMPOSE exec -T -e ES_AUTH elasticsearch sh -c "$CURL_SH" "$1" "$2" "${3:+body}") || out=$'curl failed\n000'
  code="${out##*$'\n'}"
  [[ "$code" =~ ^2 ]] || { echo "ERROR: Elasticsearch call failed ($code): $1 $2: ${out%$'\n'*}" >&2; exit 1; }
}

ready=
for _ in $(seq 1 60); do
  if printf '' | $COMPOSE exec -T -e ES_AUTH elasticsearch sh -c "$CURL_SH" GET /_cluster/health 2>/dev/null | tail -n1 | grep -q '^200$'; then ready=1; break; fi
  sleep 3
done
[[ -n "$ready" ]] || { echo "ERROR: Elasticsearch did not become ready (or rejected the elastic credentials) within 180s" >&2; exit 1; }

es PUT /_security/role/suspicious_app '{"cluster":["monitor"],"indices":[{"names":["suspicious-*"],"privileges":["create_index","index","write","read","view_index_metadata"]}]}'
es PUT /_security/role/cortex_app    '{"cluster":["monitor","manage_index_templates"],"indices":[{"names":["cortex*"],"privileges":["all"]}]}'
es PUT "/_security/user/${ES_SUSPICIOUS_USER}" "{\"password\":\"${ES_SUSPICIOUS_PASSWORD}\",\"roles\":[\"suspicious_app\"]}"
es PUT "/_security/user/${ES_CORTEX_USER}"     "{\"password\":\"${ES_CORTEX_PASSWORD}\",\"roles\":[\"cortex_app\"]}"
echo "Elasticsearch roles and users ready"
