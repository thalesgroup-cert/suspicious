#!/usr/bin/env bash
# Exit 0 only if every internal data service refuses anonymous access and
# accepts the credential from .env / .env.data.
set -uo pipefail
cd "$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="${ENV_FILE:-.env}"; DATA_ENV_FILE="${DATA_ENV_FILE:-.env.data}"
COMPOSE="${COMPOSE:-docker compose --env-file $ENV_FILE}"
set -a; . "./$ENV_FILE"; [ -f "$DATA_ENV_FILE" ] && . "./$DATA_ENV_FILE"; set +a
fail=0
check() { if eval "$2" >/dev/null 2>&1; then echo "ok    $1"; else echo "FAIL  $1"; fail=1; fi; }
# Secrets are passed as inherited env vars, never in argv.
for s in redis_broker redis_cache; do
  check "$s rejects anonymous"   "$COMPOSE exec -T $s sh -c 'unset REDISCLI_AUTH; redis-cli ping' | grep -q NOAUTH"
  check "$s accepts credential"  "$COMPOSE exec -T $s redis-cli ping | grep -q PONG"
done
es_code() {  # es_code USER:PASS or empty; secret travels as inherited env var
  A="$1" $COMPOSE exec -T -e A elasticsearch sh -c 'if [ -n "$A" ]; then printf "user = \"%s\"\n" "$A" | curl -s -K - -o /dev/null -w "%{http_code}" http://localhost:9200/_cluster/health; else curl -s -o /dev/null -w "%{http_code}" http://localhost:9200/_cluster/health; fi'
}
check "elasticsearch rejects anonymous" "[ \"\$(es_code '')\" = 401 ]"
check "elasticsearch app user ok"       "[ \"\$(es_code \"\$ES_SUSPICIOUS_USER:\$ES_SUSPICIOUS_PASSWORD\")\" = 200 ]"
check "elasticsearch cortex user ok"    "[ \"\$(es_code \"\$ES_CORTEX_USER:\$ES_CORTEX_PASSWORD\")\" = 200 ]"
check "chroma proxy rejects anonymous"  "! $COMPOSE exec -T chromadb_proxy wget -q -O /dev/null http://127.0.0.1:8000/api/v2/heartbeat"
check "chroma proxy accepts token"      "$COMPOSE exec -T chromadb_proxy sh -c 'wget -q -O /dev/null --header \"X-Chroma-Token: \$CHROMA_TOKEN\" http://127.0.0.1:8000/api/v2/heartbeat'"
check "chroma backend not on app network" "! docker inspect \$($COMPOSE ps -q chromadb) --format '{{json .NetworkSettings.Networks}}' | grep -q \"\$NETWORK_NAME\""
exit $fail
