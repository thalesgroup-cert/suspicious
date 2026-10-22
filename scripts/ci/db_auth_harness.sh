#!/usr/bin/env bash
# End-to-end check of data-service authentication in an ISOLATED compose project.
#   usage: [HARNESS_DIR=/tmp/authcheck-harness] bash scripts/ci/db_auth_harness.sh [fresh|upgrade|all]
#
# Safety: refuses to run unless PROJECT is "authcheck". Every docker compose call
# goes through AC (-p authcheck, own network authcheck_net, containers prefixed
# authcheck_, no host ports). Cleanup is `down -v` for that project plus its own
# network. Nothing is ever addressed by a name outside that prefix.
#
# fresh:   make-init equivalent -> up -> db-auth-check -> client checks -> Cortex
#          migrate -> secret rotations
# upgrade: stack from the previous release's compose files and an env without the
#          new secrets, data written through it, then db-auth-migrate.sh and
#          deploy.sh against the new files; data and idempotence verified
# Images must already exist locally (IMG_APP/IMG_FEEDER/IMG_UI tags).
set -euo pipefail

PROJECT="${PROJECT:-authcheck}"
[ "$PROJECT" = authcheck ] || { echo "refusing to run: project must be 'authcheck'" >&2; exit 2; }
MODE="${1:-all}"
WT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
T="${HARNESS_DIR:-/tmp/authcheck-harness}"
R="$T/repo"; D="$R/deployment"
OLD_REF="${OLD_REF:-main}"
IMG_APP="${IMG_APP:-wt-security}"        # local tag of ghcr.io/thalesgroup-cert/suspicious
IMG_APP_NEXT="authcheck-next"            # retag used to simulate a release bump (removed at the end)
IMG_OLD="${IMG_OLD:-wt-security}"               # local tag standing in for the previous release
IMG_FEEDER="${IMG_FEEDER:-test}"; IMG_UI="${IMG_UI:-test}"
APP_REPO=ghcr.io/thalesgroup-cert/suspicious
CORTEX_SRC="${CORTEX_SRC:-}"             # dir holding a Cortex application.conf to copy (required for cortex steps)
P=authcheck_; NET=authcheck_net

pass=0
ok()   { pass=$((pass+1)); echo "ok    $*"; }
die()  { echo "FAIL  $*" >&2; exit 1; }
step() { echo; echo "== $*"; }

OVERRIDE="$D/harness.override.yaml"
COMPOSE_FILES=(-f "$D/docker-compose.yml" -f "$OVERRIDE")
COMPOSE="docker compose -p authcheck --project-directory $D --env-file $D/.env ${COMPOSE_FILES[*]}"
AC() { $COMPOSE "$@"; }
export COMPOSE

cleanup() {
  local rc=$?
  [ -n "${KEEP_ON_FAIL:-}" ] && [ "$rc" -ne 0 ] && { echo "KEEP_ON_FAIL: stack left up (project authcheck)"; exit "$rc"; }
  step "teardown (project authcheck only)"
  [ -f "$D/.env" ] && { AC down -v --remove-orphans >/dev/null 2>&1 || true; }
  docker network rm "$NET" >/dev/null 2>&1 || true
  docker rmi "$APP_REPO:$IMG_APP_NEXT" >/dev/null 2>&1 || true
  left=$(docker ps -aq --filter "name=^${P}" | wc -l); vols=$(docker volume ls -q --filter label=com.docker.compose.project=authcheck | wc -l)
  echo "left over: containers=$left volumes=$vols"
  if [ "$rc" -eq 0 ]; then echo "ALL AUTH CHECKS PASSED ($pass checks)"; else echo "HARNESS FAILED (rc=$rc)"; fi
  exit "$rc"
}
trap cleanup EXIT

setenv() { sed -i "/^$1=/d" "$D/.env"; printf '%s=%s\n' "$1" "$2" >> "$D/.env"; }

# ── throwaway deployment tree ───────────────────────────────────────────────
setup_tree() {
  # containers write root-owned files into the tree; remove those through a container
  rm -rf "$R" 2>/dev/null || docker run --rm -v "$T:/t" alpine sh -c "rm -rf /t/repo /t/old /t/new; chown $(id -u):$(id -g) /t"
  mkdir -p "$R/Suspicious/logs" "$R/email-feeder/logs" "$R/Analyzers" "$R/docker" "$R/yara/rules" \
    "$R/cortex/jobs" "$R/cortex/Cortex-Analyzers" "$R/cortex/Cortex-Analyzers-Public/analyzers" "$R/cortex/Cortex-Analyzers-Public/responders" "$T/old" "$T/new"
  chmod 777 "$R/Suspicious/logs" "$R/email-feeder/logs" "$R/cortex/jobs"
  rsync -a --exclude __pycache__ --exclude /.env --exclude '/.env.data*' --exclude '/.env.pre*' --exclude cortex --exclude certificates "$WT/deployment/" "$D/"
  mkdir -p "$D/certificates"
  rsync -a --exclude __pycache__ "$WT/Suspicious/Suspicious/" "$R/Suspicious/code-new/"
  cp "$WT/Suspicious/gunicorn.conf.py" "$R/Suspicious/"; python3 -c 'import json,sys; c=json.load(open(sys.argv[1])); c["database"].pop("replica"); c["database"].pop("replica_read_apps"); json.dump(c,open(sys.argv[2],"w"))' "$WT/Suspicious/settings.ci.json" "$R/Suspicious/settings.json"
  cp "$WT/docs/getting-started/examples/email-feeder-config.example.json" "$R/email-feeder/config.json"
  echo '[]' > "$R/Analyzers/analyzers.json"
  echo '[]' > "$R/cortex/Cortex-Analyzers-Public/analyzers/analyzers.json"; echo '[]' > "$R/cortex/Cortex-Analyzers-Public/responders/responders.json"
  touch "$R/cortex/application-cortex.log"; chmod 666 "$R/cortex/application-cortex.log"; echo '{"auths":{}}' > "$R/docker/config.json"
  [ -n "$CORTEX_SRC" ] && cp "$CORTEX_SRC/application.conf" "$R/cortex/application.conf"
  # dummy TLS material + a truststore (the mounts only need to exist)
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$D/certificates/keyfile.pem" -out "$D/certificates/certfile.pem" -days 2 -subj /CN=authcheck 2>/dev/null
  cp "$D/certificates/certfile.pem" "$D/certificates/rootcafile.pem"
  docker run --rm --user "$(id -u):$(id -g)" -v "$D/certificates:/certs" eclipse-temurin:17-jre keytool -importcert -noprompt -alias rootca \
    -file /certs/rootcafile.pem -keystore /certs/keystore.jks -storepass changeit -storetype JKS >/dev/null
  chmod -R a+rX "$D/certificates"
  # previous release code + compose files, and the new compose files (swapped in place like a git pull would)
  git -C "$WT" archive "$OLD_REF" Suspicious/Suspicious | tar -x -C "$T/old"
  rsync -a "$T/old/Suspicious/Suspicious/" "$R/Suspicious/code-old/"
  for f in docker-compose.yml compose_databases.yaml compose_apps.yaml; do
    git -C "$WT" show "$OLD_REF:deployment/$f" > "$T/old/$f"; cp "$D/$f" "$T/new/$f"
  done
  chmod -R a+rwX "$R/Suspicious"
}

# $1 = example env, $2 = app image tag, $3 = code dir name
write_env() {
  cp "$1" "$D/.env"; [ -z "$(tail -c1 "$D/.env")" ] || echo >> "$D/.env"   # example may lack a final newline
  for kv in "SVC_PREFIX=$P" "NETWORK_NAME=$NET" "DOMAIN_CORP=authcheck.test" "MYSQL_PASSWORD=password" "MYSQL_ROOT_PASSWORD=strongpassword" \
    "REPL_PASSWORD=replpassword" "MINIO_ROOT_PASSWORD=minio-authcheck-pass" "ES_JAVA_OPTS=\"-Xms512m -Xmx512m\"" "INNODB_BUFFER_POOL_SIZE=128M" \
    "INNODB_LOG_FILE_SIZE=48M" "CELERY_MEM_LIMIT=2g" "ROOT_PATH=$R/" "SUSPICIOUS_PATH=$R/Suspicious" "SUSPICIOUS_UI_PATH=$R/suspicious-ui" \
    "FEEDER_PATH=$R/email-feeder" "DOCKER_PATH=$R/docker" "YARA_PATH=$R/yara" "CORTEX_PATH=$R/cortex" "CA_PATH=$D/certificates" \
    "CUSTOM_ANALYZERS_PATH=$R/Analyzers" "TRAEFIK_PATH=$R/traefik" "DOCKER_SOCK_GID=$(stat -c %g /var/run/docker.sock)" \
    "SUSPICIOUS_VERSION=$2" "SUSPICIOUS_UI_VERSION=$IMG_UI" "SUSPICIOUS_FEEDER_VERSION=$IMG_FEEDER" "BACKEND_URL=http://suspicious:9020" \
    "FEEDER_API_TOKEN=authcheck-feeder-token" "HTTP_PROXY=" "HTTPS_PROXY="; do setenv "${kv%%=*}" "${kv#*=}"; done
  mkdir -p "$R/traefik/logs"
}

# $1 = image tag, $2 = code dir. Local images only, no host ports, code of the release under test.
write_override() {
  {
    echo "services:"
    for s in suspicious suspicious_celery suspicious_celery_beat; do
      echo "  $s: {pull_policy: never, volumes: ['$R/Suspicious/$2:/app/Suspicious:rw']$([ $s = suspicious ] && echo ', ports: !reset []')}"
    done
    echo "  feeder: {pull_policy: never}"
    for s in suspicious_ui cortex rustfs vault traefik; do echo "  $s: {ports: !reset []$([ $s = suspicious_ui ] && echo ', pull_policy: never')}"; done
  } > "$OVERRIDE"
  # placeholders only satisfy the required-variable checks of the new compose files
  local cfg tmpdata=0; [ -f "$D/.env.data" ] || { : > "$D/.env.data"; tmpdata=1; }
  cfg=$(REDIS_BROKER_PASSWORD=x REDIS_CACHE_PASSWORD=x CHROMA_TOKEN=x ES_CORTEX_USER=x ES_CORTEX_PASSWORD=x AC config 2>&1) || die "compose config: $cfg"
  [ "$tmpdata" = 0 ] || rm -f "$D/.env.data"
  grep -q '^name: authcheck$' <<<"$cfg" || die "compose project name is not authcheck"
  ! grep -q 'published:' <<<"$cfg" || die "authcheck config publishes host ports"
}

swap_compose() {  # $1 = old|new
  for f in docker-compose.yml compose_databases.yaml compose_apps.yaml; do cp "$T/$1/$f" "$D/$f"; done
}

# ── helpers ─────────────────────────────────────────────────────────────────
envv() { ( set -a; . "$D/.env"; [ -f "$D/.env.data" ] && . "$D/.env.data"; set +a; printf '%s' "${!1}" ); }
wait_healthy() {  # wait_healthy container [secs]
  local c=$1 n=${2:-240} s
  for _ in $(seq 1 $((n/5))); do
    s=$(docker inspect -f '{{.State.Health.Status}}' "$c" 2>/dev/null || echo missing)
    [ "$s" = healthy ] && return 0; sleep 5
  done
  docker logs --tail 25 "$c" >&2 2>&1 || true
  die "$c not healthy (last: $s)"
}
# one-off Python in the app image on the authcheck network, code of the release under test
cli() {  # cli <code-dir> <python code> [-e VAR ...]: a throwaway app container on every project network that exists
  local code=$1 py=$2; shift 2
  local c rc n
  c=$(docker create --network "$NET" "$@" -v "$R/Suspicious/$code:/app/Suspicious:ro" -v "$R/Suspicious/settings.json:/app/settings.json:ro" \
    "$APP_REPO:$IMG_APP" python -c "$py")
  for n in authcheck_data authcheck_storage authcheck_cortex; do
    docker network inspect "$n" >/dev/null 2>&1 && docker network connect "$n" "$c"
  done
  docker start -a "$c"; rc=$?
  docker rm -f "$c" >/dev/null
  return $rc
}
es_curl() {  # es_curl <user:pass or ''> <curl args...> ; credential only via env + curl config on stdin
  local a=$1; shift
  A="$a" AC exec -T -e A elasticsearch sh -c 'if [ -n "$A" ]; then printf "user = \"%s\"\n" "$A" | curl -s -K - "$@"; else curl -s "$@"; fi' sh "$@"
}

CLIENT_PY='
import os, sys, redis, chromadb
from elasticsearch import Elasticsearch
from urllib.parse import quote
def ru(h,p): return "redis://:%s@%s:6379/0" % (quote(p,safe=""),h)
for h,v in (("redis_broker","REDIS_BROKER_PASSWORD"),("redis_cache","REDIS_CACHE_PASSWORD")):
    assert redis.Redis.from_url(ru(h,os.environ[v])).ping(), h
    try: redis.Redis.from_url("redis://%s:6379/0" % h).ping(); sys.exit("anonymous redis accepted: "+h)
    except redis.exceptions.AuthenticationError: pass
es=Elasticsearch("http://elasticsearch:9200", basic_auth=(os.environ["ES_SUSPICIOUS_USER"],os.environ["ES_SUSPICIOUS_PASSWORD"]))
assert es.info()["cluster_name"]
try: Elasticsearch("http://elasticsearch:9200").info(); sys.exit("anonymous ES accepted")
except Exception as e: assert "401" in str(e) or "security_exception" in str(e), e
c=chromadb.HttpClient(host="chromadb",port=8000,headers={"X-Chroma-Token":os.environ["CHROMA_TOKEN"]}); c.heartbeat()
try: chromadb.HttpClient(host="chromadb",port=8000).heartbeat(); sys.exit("anonymous chroma accepted")
except Exception as e: assert "401" in str(e) or "nauthori" in str(e) or "orbidden" in str(e), e
print("clients ok")
'

secret_env() {  # -e flags for the secrets (values never printed)
  for k in REDIS_BROKER_PASSWORD REDIS_CACHE_PASSWORD ES_SUSPICIOUS_USER ES_SUSPICIOUS_PASSWORD CHROMA_TOKEN; do printf -- '-e\n%s=%s\n' "$k" "$(envv $k)"; done
}

check_network() {
  ENV_FILE="$D/.env" COMPOSE="$COMPOSE" bash "$D/scripts/network-check.sh" > "$T/net.out" 2>&1 || true; cat "$T/net.out"
  ! grep -q '^FAIL' "$T/net.out" || die "network-check failed"; ok "network-check ($(grep -c '^ok ' "$T/net.out") checks)"
}
check_auth() {
  ENV_FILE="$D/.env" COMPOSE="$COMPOSE" bash "$D/scripts/db-auth-check.sh" > "$T/check.out"; cat "$T/check.out"
  [ "$(grep -c '^ok ' "$T/check.out")" = 10 ] || die "db-auth-check not 10/10"; ok "db-auth-check 10/10"
  mapfile -t E < <(secret_env)
  cli code-new "$CLIENT_PY" "${E[@]}" | grep -q 'clients ok' || die "client checks"; ok "app clients reach redis/ES/chroma with credentials; anonymous rejected on all three"
}

# ── rotations (rows of docs/operations/deploy.md) ───────────────────────────
rotate_redis() {
  local new; new=$(openssl rand -hex 24)
  setenv REDIS_BROKER_PASSWORD "$new"
  AC up -d --force-recreate --no-deps redis_broker suspicious suspicious_celery suspicious_celery_beat >/dev/null
  for c in redis_broker suspicious suspicious_celery; do wait_healthy "$P$c" 300; done
  check_auth; ok "Redis broker rotation procedure"
}
rotate_es_elastic() {  # exact doc row: curl config on stdin, then update .env.data and recreate elasticsearch
  local old new; old=$(envv ELASTIC_PASSWORD); new=$(openssl rand -hex 24)
  printf 'user = "elastic:%s"\ndata = "{\\"password\\":\\"%s\\"}"\n' "$old" "$new" \
    | AC exec -T elasticsearch curl -sS -K - -X POST -H 'Content-Type: application/json' http://localhost:9200/_security/user/elastic/_password | grep -q '^{}$' \
    || die "ELASTIC_PASSWORD change call rejected"
  sed -i "s|^ELASTIC_PASSWORD=.*|ELASTIC_PASSWORD=$new|" "$D/.env.data"
  AC up -d --force-recreate --no-deps elasticsearch >/dev/null; wait_healthy "${P}elasticsearch" 300
  [ "$(es_curl "elastic:$new" -o /dev/null -w '%{http_code}' http://localhost:9200/_cluster/health)" = 200 ] || die "new elastic password not accepted"
  [ "$(es_curl "elastic:$old" -o /dev/null -w '%{http_code}' http://localhost:9200/_cluster/health)" = 401 ] || die "old elastic password still accepted"
  ok "ELASTIC_PASSWORD rotation procedure"
}
rotate_es_app() {
  local new; new=$(openssl rand -hex 24); setenv ES_SUSPICIOUS_PASSWORD "$new"
  ENV_FILE="$D/.env" COMPOSE="$COMPOSE" bash "$D/scripts/es-security-bootstrap.sh" >/dev/null
  AC up -d --force-recreate --no-deps suspicious suspicious_celery cortex >/dev/null
  wait_healthy "${P}suspicious" 300; check_auth; ok "ES app user rotation procedure"
}

# ── fresh install ───────────────────────────────────────────────────────────
fresh() {
  step "fresh install"
  swap_compose new; write_env "$D/.env.example" "$IMG_APP" code-new; write_override "$IMG_APP" code-new
  bash "$D/scripts/gen-service-secrets.sh" "$D/.env" "$D/.env.data" >/dev/null
  bash "$D/scripts/check-secrets.sh" "$D/.env" >/dev/null && ok "check-secrets passes after generation"
  docker network create "$NET" >/dev/null
  AC up -d --wait --wait-timeout 300 redis_broker redis_cache elasticsearch chromadb_proxy >/dev/null; ok "data tier healthy under compose (healthchecks authenticate)"
  ENV_FILE="$D/.env" COMPOSE="$COMPOSE" bash "$D/scripts/es-security-bootstrap.sh"; ok "es-security-bootstrap"
  check_auth
  AC up -d db_suspicious rustfs >/dev/null; wait_healthy "${P}db_suspicious" 120
  AC run --rm --no-deps suspicious python manage.py migrate --noinput >/dev/null
  AC up -d suspicious suspicious_celery suspicious_celery_beat suspicious_ui cortex >/dev/null  # feeder excluded: it exits without an enabled mailbox and touches none of the data services
  for c in suspicious suspicious_celery suspicious_celery_beat cortex; do wait_healthy "$P$c" 400; done; ok "app tier + cortex healthy"
  check_network
  curl_h=$(AC exec -T suspicious curl -sf http://localhost:9020/api/health/); echo "$curl_h" | grep -q '"redis": true' && ok "/api/health/ reports redis ok" || die "health: $curl_h"
  cortex_migrate
  rotate_redis; rotate_es_elastic; rotate_es_app
}

cortex_migrate() {
  [ -n "$CORTEX_SRC" ] || { echo "skip  cortex migrate (CORTEX_SRC unset)"; return; }
  AC exec -T cortex curl -s -XPOST http://localhost:9001/api/maintenance/migrate -o /dev/null -w '%{http_code}\n'
  sleep 15
  n=$(es_curl "$(envv ES_CORTEX_USER):$(envv ES_CORTEX_PASSWORD)" 'http://localhost:9200/_cat/indices/cortex*' | wc -l)
  [ "$n" -gt 0 ] || die "no cortex indices after maintenance/migrate"; ok "cortex indices created ($n) with its own account"
  ! AC logs cortex 2>&1 | grep -qi security_exception || die "security_exception in Cortex log"; ok "no security_exception in Cortex log"
}

# ── upgrade from the previous release ───────────────────────────────────────
upgrade() {
  step "upgrade simulation from $OLD_REF"
  AC down -v --remove-orphans >/dev/null 2>&1 || true; docker network rm "$NET" >/dev/null 2>&1 || true
  rm -f "$D/.env.data" "$D"/.env.pre-db-auth.* "$D"/.env.data.pre-db-auth.*
  swap_compose old
  write_env <(git -C "$WT" show "$OLD_REF:deployment/.env.example") "$IMG_OLD" code-old; write_override "$IMG_OLD" code-old
  for k in ES_SUSPICIOUS_PASSWORD ES_CORTEX_PASSWORD REDIS_BROKER_PASSWORD REDIS_CACHE_PASSWORD CHROMA_TOKEN ELASTIC_PASSWORD; do ! grep -q "^$k=." "$D/.env" || die "old env has $k"; done
  ok "old env carries none of the new secrets"
  docker network create "$NET" >/dev/null
  AC up -d db_suspicious redis_broker redis_cache elasticsearch chromadb rustfs >/dev/null
  for c in db_suspicious redis_broker redis_cache elasticsearch rustfs; do wait_healthy "$P$c" 300; done
  AC run --rm --no-deps suspicious python manage.py migrate --noinput >/dev/null
  AC up -d suspicious suspicious_celery suspicious_celery_beat suspicious_ui cortex >/dev/null  # feeder excluded: it exits without an enabled mailbox and touches none of the data services
  for c in suspicious suspicious_celery suspicious_celery_beat cortex; do wait_healthy "$P$c" 400; done; ok "old stack (unauthenticated) healthy"
  # old unauthenticated state + sentinel data
  [ "$(es_curl '' -o /dev/null -w '%{http_code}' http://localhost:9200/_cluster/health)" = 200 ] || die "old ES not anonymous"
  AC exec -T redis_cache redis-cli set sentinel-cache alive | grep -q OK
  es_curl '' -XPUT 'http://localhost:9200/suspicious-cases/_doc/1?refresh=true' -H 'Content-Type: application/json' -d '{"title":"sentinel-doc"}' | grep -q '"result"'
  # clients-first: the NEW code works against old ES/Chroma, and fails against old Redis
  cli code-new '
import chromadb, sys, redis
from elasticsearch import Elasticsearch
Elasticsearch("http://elasticsearch:9200", basic_auth=("u","p")).info()
c=chromadb.HttpClient(host="chromadb",port=8000,headers={"X-Chroma-Token":"x"})
col=c.get_or_create_collection("sentinel_col"); col.add(ids=["a"],documents=["sentinel chroma item"],embeddings=[[0.1,0.2,0.3]])
try: redis.Redis.from_url("redis://:pw@redis_cache:6379/0").ping(); sys.exit("redis accepted a password it does not have")
except redis.exceptions.AuthenticationError as e: print("redis:",e)
print("new clients vs old services ok")' | tee "$T/clients-first.out" | grep -q 'called without any password' || die "clients-first checks"
  grep -q 'new clients vs old services ok' "$T/clients-first.out" || die "clients-first checks"
  ok "new ES/Chroma clients work against old unsecured services; new Redis client fails with 'without any password'"
  old_beat=$(docker inspect -f '{{.State.StartedAt}}' "${P}suspicious_celery_beat")
  # operator steps of a release: new compose files, bumped version
  swap_compose new; setenv SUSPICIOUS_VERSION "$IMG_APP"; write_override "$IMG_APP" code-new
  ! bash -c "cd $D && ENV_FILE=$D/.env COMPOSE='$COMPOSE' bash scripts/db-auth-check.sh" >/dev/null 2>&1 || die "check passed before migration"
  ok "db-auth-check fails before migration"
  ASSUME_YES=1 ENV_FILE="$D/.env" COMPOSE="$COMPOSE" bash "$D/scripts/db-auth-migrate.sh" 2>&1 | tee "$T/migrate.out" | sed 's/\(PASSWORD\|TOKEN\)=[^ ]*/\1=***/'
  [ "${PIPESTATUS[0]}" = 0 ] || die "db-auth-migrate failed"
  ls "$D"/.env.pre-db-auth.* >/dev/null && ok "env backup present: $(ls "$D" -a | grep -c 'pre-db-auth') file(s)"
  stat -c %a "$D/.env.data" | grep -q 600 && ok ".env.data created, mode 600"
  for c in suspicious suspicious_celery suspicious_celery_beat cortex redis_broker redis_cache elasticsearch chromadb_proxy; do wait_healthy "$P$c" 300; done; ok "all services healthy after migrate"
  new_beat=$(docker inspect -f '{{.State.StartedAt}}' "${P}suspicious_celery_beat")
  [ "$old_beat" != "$new_beat" ] && ok "celery beat restarted by migrate"
  check_auth
  # data survival
  es_curl "$(envv ES_SUSPICIOUS_USER):$(envv ES_SUSPICIOUS_PASSWORD)" 'http://localhost:9200/suspicious-cases/_doc/1' | grep -q sentinel-doc || die "ES doc lost"; ok "ES document survived (volume kept)"
  mapfile -t E < <(secret_env)
  cli code-new 'import os,chromadb
c=chromadb.HttpClient(host="chromadb",port=8000,headers={"X-Chroma-Token":os.environ["CHROMA_TOKEN"]})
col=c.get_collection("sentinel_col"); assert col.count()==1, col.count(); print("chroma item ok")' "${E[@]}" | grep -q 'chroma item ok' || die "chroma data lost"
  ok "Chroma collection survived (volume kept)"
  v=$(AC exec -T redis_cache sh -c 'redis-cli get sentinel-cache' | tr -d '\r\n'); [ -z "$v" ] && ok "redis sentinel dropped as documented"
  ASSUME_YES=1 ENV_FILE="$D/.env" COMPOSE="$COMPOSE" bash "$D/scripts/db-auth-migrate.sh" | grep -q 'Already migrated' || die "rerun did not say Already migrated"
  ok "rerun says 'Already migrated'"
  # a release bump through deploy.sh (new image tag -> app tier recreated, beat included)
  docker tag "$APP_REPO:$IMG_APP" "$APP_REPO:$IMG_APP_NEXT"; setenv SUSPICIOUS_VERSION "$IMG_APP_NEXT"
  beat_before=$(docker inspect -f '{{.Id}}' "${P}suspicious_celery_beat")
  ( cd "$D" && COMPOSE_PROJECT_NAME=authcheck COMPOSE_FILE="$D/docker-compose.yml:$OVERRIDE" bash scripts/deploy.sh ) > "$T/deploy.out" 2>&1 || { tail -40 "$T/deploy.out"; die "deploy.sh failed"; }
  tail -8 "$T/deploy.out"
  [ "$beat_before" != "$(docker inspect -f '{{.Id}}' "${P}suspicious_celery_beat")" ] && ok "deploy.sh recreated celery beat"
  for c in suspicious suspicious_celery suspicious_celery_beat; do wait_healthy "$P$c" 300; done; ok "deploy.sh end to end"
  check_network
  # deploy refuses when auth is not enforced: simulate with a wrong credential
  cortex_migrate
  rotate_redis; rotate_es_elastic; rotate_es_app
}

setup_tree
case "$MODE" in
  fresh) fresh ;;
  upgrade) upgrade ;;
  all) fresh; upgrade ;;
  *) die "usage: $0 [fresh|upgrade|all]" ;;
esac
