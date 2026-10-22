#!/usr/bin/env bash
# Unseal the Vault container.
#
# Default: the operator types the unseal keys when asked. Vault's own hidden
# prompt reads them, so a key never reaches a command line, a file or a log:
# `make unseal`, from a terminal, once per Vault restart.
#
# Idempotent and safe to run at every boot: it no-ops when Vault is already
# unsealed or unreachable, and when there is no terminal to ask on (make up,
# make deploy from CI or cron) it leaves Vault sealed with a clear message
# instead of blocking.
#
# Legacy: if a keys file exists (vault/unseal.keys, or VAULT_UNSEAL_KEYS_FILE) it
# is still used, one key per line. That keeps the keys on the same host as
# Vault, so whoever can read the file can unseal it; delete it and unseal by
# hand, or use Vault auto-unseal (cloud KMS / transit Vault) in production —
# see VAULT.md.
set -euo pipefail

DEPLOY_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$DEPLOY_DIR"           # so `docker compose` resolves .env + COMPOSE_FILE
KEYS_FILE="${VAULT_UNSEAL_KEYS_FILE:-$DEPLOY_DIR/vault/unseal.keys}"
VAULT_SVC="${VAULT_SVC:-vault}"

# Run the vault CLI inside the running Vault container (no host CLI required).
# stdin is tied to /dev/null: `docker compose exec` would otherwise swallow the
# caller's stdin — inside the unseal `while read` loop that ate the remaining
# keys after the first, stalling unseal at 1/3.
vault() {
  docker compose --env-file .env exec -T \
    -e VAULT_ADDR=https://127.0.0.1:8200 -e VAULT_CACERT=/vault/ca/ca.pem "$VAULT_SVC" vault "$@" </dev/null
}

# Echo the seal state: unsealed | sealed | down.
# `vault status` exits 0 when unsealed, 2 when sealed, other when unreachable.
seal_state() {
  if vault status >/dev/null 2>&1; then
    echo unsealed
  else
    case $? in
      2) echo sealed ;;
      *) echo down ;;
    esac
  fi
}

# Wait up to ~30s for the container to answer at all (it may still be booting).
for _ in $(seq 1 30); do
  [ "$(seal_state)" != down ] && break
  sleep 1
done

case "$(seal_state)" in
  unsealed)
    echo "Vault already unsealed."
    exit 0 ;;
  down)
    echo "WARN: Vault not reachable; skipping unseal." >&2
    exit 0 ;;
esac

if [ ! -f "$KEYS_FILE" ]; then
  if [ ! -t 0 ] || [ ! -t 1 ]; then
    echo "Vault is sealed and there is no terminal to ask for the unseal keys." >&2
    echo "      Run 'make unseal' from a terminal and type them in." >&2
    exit 0
  fi
  echo "Vault is sealed. Enter unseal keys (hidden) until it opens; Ctrl-C to stop."
  attempts=0
  while [ "$(seal_state)" = sealed ] && [ "$attempts" -lt 10 ]; do
    attempts=$((attempts + 1))
    # A TTY exec (no -T, stdout left on the terminal, or no TTY is allocated):
    # Vault reads the key from its own hidden prompt and prints only the seal
    # progress, never the key.
    docker compose --env-file .env exec \
      -e VAULT_ADDR=https://127.0.0.1:8200 -e VAULT_CACERT=/vault/ca/ca.pem \
      "$VAULT_SVC" vault operator unseal || echo "  key rejected." >&2
  done
  if [ "$(seal_state)" = unsealed ]; then
    echo "Vault unsealed."
    exit 0
  fi
  echo "ERROR: Vault still sealed." >&2
  exit 1
fi

echo "WARN: using unseal keys stored on this host ($KEYS_FILE); see VAULT.md for the alternatives." >&2

# Emit one unseal key per line. Tolerates both a bare "<key>" per line and the
# verbose `vault operator init` layout ("Unseal Key 1: <key>"); strips inline
# comments and ignores the root-token line.
read_keys() {
  sed 's/#.*//' "$KEYS_FILE" | awk '
    /[Rr]oot [Tt]oken/ { next }            # never treat the root token as a key
    {
      line = $0
      sub(/^.*:[[:space:]]*/, "", line)    # drop a "Label:" prefix if present
      gsub(/[[:space:]]/, "", line)        # drop all whitespace (incl. CR)
      if (line != "") print line
    }
  '
}

echo "Unsealing Vault with keys from $KEYS_FILE …"
applied=0
while IFS= read -r key; do
  [ -z "$key" ] && continue
  applied=$((applied + 1))
  if ! out=$(vault operator unseal "$key" 2>&1); then
    echo "  key #$applied rejected: ${out##*$'\n'}" >&2
  fi
  [ "$(seal_state)" = unsealed ] && break
done < <(read_keys)

if [ "$(seal_state)" = unsealed ]; then
  echo "Vault unsealed."
else
  echo "ERROR: Vault still sealed after applying $applied key(s) from $KEYS_FILE" >&2
  echo "       Check the file holds enough distinct unseal keys (see Threshold below)," >&2
  echo "       one key per line. Current status:" >&2
  vault status 2>&1 | sed 's/^/       /' >&2 || true
  exit 1
fi
