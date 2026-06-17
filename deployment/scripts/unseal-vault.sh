#!/usr/bin/env bash
# Unseal the Vault container using operator unseal keys stored on the host.
#
# Idempotent and safe to run at every boot: it no-ops when Vault is already
# unsealed, when Vault is unreachable, or when no keys file is present — so it
# never blocks `make up` on an uninitialised or Vault-less setup.
#
# SECURITY: the unseal keys live on the same host as Vault
# (vault/unseal.keys, gitignored, chmod 600). This trades away part of the
# seal's protection — whoever can read the file can unseal Vault. Acceptable
# for a single-host dev/staging deployment; for production use Vault
# auto-unseal backed by a cloud KMS or a transit Vault instead.
set -euo pipefail

DEPLOY_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$DEPLOY_DIR"           # so `docker compose` resolves .env + COMPOSE_FILE
KEYS_FILE="${VAULT_UNSEAL_KEYS_FILE:-$DEPLOY_DIR/vault/unseal.keys}"
VAULT_SVC="${VAULT_SVC:-vault}"

# Run the vault CLI inside the running Vault container (no host CLI required).
vault() {
  docker compose --env-file .env exec -T \
    -e VAULT_ADDR=http://127.0.0.1:8200 "$VAULT_SVC" vault "$@"
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
  echo "WARN: no unseal keys at $KEYS_FILE — Vault left sealed." >&2
  echo "      Run 'make provision-vault' prerequisites: 'vault operator init'," >&2
  echo "      then write the unseal keys (one per line) to that file." >&2
  exit 0
fi

echo "Unsealing Vault with keys from $KEYS_FILE …"
while IFS= read -r line; do
  key="${line%%#*}"                         # strip inline comments
  key="$(printf '%s' "$key" | tr -d '[:space:]')"
  [ -z "$key" ] && continue
  vault operator unseal "$key" >/dev/null || true
  [ "$(seal_state)" = unsealed ] && break
done < "$KEYS_FILE"

if [ "$(seal_state)" = unsealed ]; then
  echo "Vault unsealed."
else
  echo "ERROR: Vault still sealed after applying keys from $KEYS_FILE" >&2
  exit 1
fi
