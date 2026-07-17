#!/usr/bin/env bash
# Provision Vault for Suspicious: enable KV v2 at suspicious/, write the
# suspicious-read AppRole policy, create the AppRole, and emit role_id /
# secret_id into deployment/.env. Vault runs as a Docker Compose service, so
# every vault command is executed inside that container. Requires VAULT_TOKEN
# (root or admin) in the environment.
set -euo pipefail

: "${VAULT_TOKEN:?set VAULT_TOKEN (root/admin) for provisioning}"
export VAULT_TOKEN

DEPLOY_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$DEPLOY_DIR"           # so `docker compose` resolves .env + COMPOSE_FILE
ENV_FILE="$DEPLOY_DIR/.env"

VAULT_SVC="${VAULT_SVC:-vault}"
# Run the vault CLI inside the running Vault container (no host CLI required).
vault() {
  docker compose --env-file .env exec -T \
    -e VAULT_TOKEN -e VAULT_ADDR=http://127.0.0.1:8200 \
    "$VAULT_SVC" vault "$@"
}

vault secrets enable -path=suspicious kv-v2 2>/dev/null || true

vault policy write suspicious-read - <<'EOF'
path "suspicious/data/*"     { capabilities = ["read"] }
path "suspicious/metadata/*" { capabilities = ["read", "list"] }
# Connector secret editing from the Settings UI writes integration secrets
# straight to Vault. Scoped create/update so admins can set/rotate them;
# boot-critical and non-connector secrets stay read-only above.
path "suspicious/data/integrations/*" { capabilities = ["create", "update", "read"] }
EOF

vault auth enable approle 2>/dev/null || true
vault write auth/approle/role/suspicious \
  token_policies="suspicious-read" token_ttl=1h token_max_ttl=4h

ROLE_ID=$(vault read -field=role_id auth/approle/role/suspicious/role-id)
SECRET_ID=$(vault write -f -field=secret_id auth/approle/role/suspicious/secret-id)

sed -i '/^VAULT_ROLE_ID=/d;/^VAULT_SECRET_ID=/d' "$ENV_FILE" 2>/dev/null || true
{
  echo "VAULT_ROLE_ID=${ROLE_ID}"
  echo "VAULT_SECRET_ID=${SECRET_ID}"
} >> "$ENV_FILE"
echo "AppRole credentials written to ${ENV_FILE}"
