#!/usr/bin/env bash
# Exit 0 only if every service sits on exactly the networks it needs and the
# paths it needs still work. Membership is read from Docker (isolation between
# bridge networks is what stops a compromised peer); reachability is probed from
# the containers that must keep working.
set -uo pipefail
cd "$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="$(realpath "${ENV_FILE:-.env}")"
DATA_ENV_FILE="$(realpath "${DATA_ENV_FILE:-$(dirname "$ENV_FILE")/.env.data}")"
COMPOSE="${COMPOSE:-docker compose --env-file $ENV_FILE}"
set -a; . "$ENV_FILE"; [ -f "$DATA_ENV_FILE" ] && . "$DATA_ENV_FILE"; set +a
P="$($COMPOSE config --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)["name"])')"
fail=0
check() { if eval "$2" >/dev/null 2>&1; then echo "ok    $1"; else echo "FAIL  $1"; fail=1; fi; }

running() { [ -n "$($COMPOSE ps -q --status running "$1" 2>/dev/null)" ]; }   # a service that is not up is not judged
nets() { docker inspect "$($COMPOSE ps -q "$1")" --format '{{range $k, $_ := .NetworkSettings.Networks}}{{$k}} {{end}}'; }
# exactly: the service's networks are the listed ones (suspicious_network is $NETWORK_NAME)
exactly() {
  local svc=$1; shift
  running "$svc" || { echo "      $svc not running, skipped" >&2; return 0; }
  local want; want=$(for n in "$@"; do [ "$n" = suspicious_network ] && echo "$NETWORK_NAME" || echo "${P}_$n"; done | sort | tr '\n' ' ')
  local have; have=$(nets "$svc" | tr ' ' '\n' | sed '/^$/d' | sort | tr '\n' ' ')
  [ "$want" = "$have" ] || { echo "      $svc is on: $have (want: $want)" >&2; return 1; }
}
check "db_suspicious only on data"           "exactly db_suspicious data"
check "redis_broker only on data"            "exactly redis_broker data"
check "redis_cache only on data"             "exactly redis_cache data"
check "chromadb_proxy on data and its backend link" "exactly chromadb_proxy data chroma_internal"
check "chromadb only on its backend link"    "exactly chromadb chroma_internal"
check "elasticsearch only on cortex"         "exactly elasticsearch cortex"
check "rustfs only on storage"               "exactly rustfs storage"
check "cortex only on cortex"                "exactly cortex cortex"
check "feeder on app and storage, not data"  "exactly feeder suspicious_network storage"
check "suspicious_ui off the data tier"      "! running suspicious_ui || ! nets suspicious_ui | grep -qE '${P}_(data|storage|cortex)'"
check "django on all four tiers"             "exactly suspicious suspicious_network data storage cortex"
check "celery on all four tiers"             "exactly suspicious_celery suspicious_network data storage cortex"
check "beat on app and data"                 "exactly suspicious_celery_beat suspicious_network data"

py_reach() {  # py_reach service host port
  running "$1" || return 0
  $COMPOSE exec -T "$1" python3 -c 'import socket,sys; socket.create_connection((sys.argv[1], int(sys.argv[2])), 3)' "$2" "$3"
}
for hp in db_suspicious:3306 redis_broker:6379 redis_cache:6379 elasticsearch:9200 rustfs:9000 chromadb:8000 cortex:9001; do
  check "django reaches ${hp%%:*}"   "py_reach suspicious ${hp%%:*} ${hp##*:}"
done
for hp in db_suspicious:3306 redis_broker:6379 elasticsearch:9200 rustfs:9000 chromadb:8000 cortex:9001; do
  check "celery reaches ${hp%%:*}"   "py_reach suspicious_celery ${hp%%:*} ${hp##*:}"
done
check "beat reaches db and redis"    "py_reach suspicious_celery_beat db_suspicious 3306 && py_reach suspicious_celery_beat redis_broker 6379"
check "feeder reaches django and rustfs" "py_reach feeder suspicious 9020 && py_reach feeder rustfs 9000"
check "cortex reaches elasticsearch and django" \
  "! running cortex || $COMPOSE exec -T cortex bash -c 'exec 3<>/dev/tcp/elasticsearch/9200 && exec 4<>/dev/tcp/suspicious/9020'"
# what must NOT resolve: Docker DNS only answers for names on a shared network
nores() { ! running "$1" || ! $COMPOSE exec -T "$1" python3 -c 'import socket,sys; socket.gethostbyname(sys.argv[1])' "$2"; }
check "feeder cannot resolve redis_broker or db_suspicious" "nores feeder redis_broker && nores feeder db_suspicious"
exit $fail
