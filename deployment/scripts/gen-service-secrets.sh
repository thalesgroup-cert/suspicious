#!/usr/bin/env bash
# Fill empty/missing data-service secrets with random hex. Never overwrites an
# existing value, so re-running `make init` is safe.
#   usage: gen-service-secrets.sh [env-file] [data-env-file]
# ELASTIC_PASSWORD (Elasticsearch superuser) goes to the data env file
# (default: .env.data next to the env file); everything else to the env file.
set -euo pipefail
ENV_FILE="$(realpath "${1:-.env}")"
DATA_ENV_FILE="$(realpath "${2:-$(dirname "$ENV_FILE")/.env.data}")"
touch "$ENV_FILE" "$DATA_ENV_FILE"; chmod 600 "$ENV_FILE" "$DATA_ENV_FILE"
# a file without a final newline would swallow the first appended key
for f in "$ENV_FILE" "$DATA_ENV_FILE"; do [ -s "$f" ] && [ -n "$(tail -c1 "$f")" ] && echo >> "$f"; done

fill() {  # fill FILE KEY VALUE
  local f="$1" k="$2" val="$3"
  grep -Eq "^${k}=.+" "$f" && return 0
  if grep -q "^${k}=" "$f"; then sed -i "s|^${k}=.*|${k}=${val}|" "$f"
  else printf '%s=%s\n' "$k" "$val" >> "$f"; fi
  echo "-> set $k in $f"
}
gen() {  # gen FILE KEY: random hex; a failing openssl must never leave "KEY=" behind
  grep -Eq "^${2}=.+" "$1" && return 0
  local val; val=$(openssl rand -hex 24) || exit 1
  fill "$1" "$2" "$val"
}
for k in REDIS_BROKER_PASSWORD REDIS_CACHE_PASSWORD ES_SUSPICIOUS_PASSWORD ES_CORTEX_PASSWORD CHROMA_TOKEN; do gen "$ENV_FILE" "$k"; done
gen "$DATA_ENV_FILE" ELASTIC_PASSWORD
fill "$ENV_FILE" ES_SUSPICIOUS_USER suspicious_app
fill "$ENV_FILE" ES_CORTEX_USER cortex_app
