#!/usr/bin/env bash
# Generate the TLS material for the Vault listener (idempotent; no-op when it
# already exists).
#
#   vault/tls/vault.pem + vault.key   server certificate and key, mounted into
#                                     the Vault container only
#   vault/ca/ca.pem                   the CA that signed it, public, mounted into
#                                     the app containers as VAULT_CACERT
#
# The certificate carries SANs (vault, localhost, 127.0.0.1): hvac and the Go
# Vault CLI ignore the CN and reject a certificate without them. It is signed by
# a Vault-only CA so trusting it does not trust anything else in the stack.
# The key is handed to the container's `vault` user (uid 100) with mode 640, so
# it is not world-readable on the host.
#
# Set VAULT_TLS_FORCE=1 to regenerate (rotation); restart Vault afterwards and
# unseal it. VAULT_TLS_DAYS (default 825) sets the server certificate lifetime.
set -euo pipefail

DEPLOY_DIR="$(cd "$(dirname "$0")/.." && pwd)"
VAULT_DIR="${VAULT_PATH:-$DEPLOY_DIR/vault}"
TLS_DIR="$VAULT_DIR/tls"
CA_DIR="$VAULT_DIR/ca"
DAYS="${VAULT_TLS_DAYS:-825}"
VAULT_UID=100   # `vault` in the hashicorp/vault image; also the owner of vault/data

if [ -f "$TLS_DIR/vault.pem" ] && [ -f "$TLS_DIR/vault.key" ] && [ -f "$CA_DIR/ca.pem" ] \
   && [ "${VAULT_TLS_FORCE:-0}" != 1 ]; then
  echo "Vault TLS material already present."
else
  mkdir -p "$TLS_DIR" "$CA_DIR"
  work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT

  openssl genrsa -out "$work/ca.key" 4096 2>/dev/null
  openssl req -x509 -new -nodes -key "$work/ca.key" -sha256 -days 3650 \
    -subj "/O=Suspicious/CN=Suspicious Vault CA" -out "$work/ca.pem"

  openssl genrsa -out "$work/vault.key" 2048 2>/dev/null
  openssl req -new -key "$work/vault.key" -subj "/O=Suspicious/CN=vault" -out "$work/vault.csr"
  printf 'subjectAltName=DNS:vault,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > "$work/ext.cnf"
  openssl x509 -req -in "$work/vault.csr" -CA "$work/ca.pem" -CAkey "$work/ca.key" \
    -CAcreateserial -days "$DAYS" -sha256 -extfile "$work/ext.cnf" -out "$work/vault.pem" 2>/dev/null

  install -m 644 "$work/ca.pem" "$CA_DIR/ca.pem"
  install -m 644 "$work/vault.pem" "$TLS_DIR/vault.pem"
  install -m 640 "$work/vault.key" "$TLS_DIR/vault.key"
  # The CA key is not kept: a certificate is re-issued by regenerating the pair.
  # Hand the server key to the container user; the host user keeps group read.
  # (A throwaway container, so no sudo is needed on the host.)
  docker run --rm -v "$TLS_DIR:/t" --entrypoint sh hashicorp/vault:1.18 \
    -c "chown $VAULT_UID:$(id -g) /t/vault.key /t && chmod 750 /t"
  echo "Vault TLS material written to $TLS_DIR and $CA_DIR (valid ${DAYS} days)."
fi

# An existing deployment points VAULT_ADDR at http://vault:8200; the listener
# now speaks TLS, so move it to https (the env file is backed up first).
ENV_FILE="$DEPLOY_DIR/.env"
if [ -f "$ENV_FILE" ] && grep -q '^VAULT_ADDR=http://' "$ENV_FILE"; then
  cp "$ENV_FILE" "$ENV_FILE.bak-vault-tls"
  sed -i 's#^VAULT_ADDR=http://#VAULT_ADDR=https://#' "$ENV_FILE"
  echo "VAULT_ADDR in .env now uses https (backup: .env.bak-vault-tls)."
fi
