#!/usr/bin/env bash
# Provision Vault for Suspicious: enable KV v2 at suspicious/, write the
# suspicious-read AppRole policy, create the AppRole, and emit role_id /
# secret_id into deployment/.env. Requires VAULT_ADDR + VAULT_TOKEN (root or
# an admin token) in the environment.
set -euo pipefail

: "${VAULT_ADDR:?set VAULT_ADDR (e.g. http://127.0.0.1:8200)}"
: "${VAULT_TOKEN:?set VAULT_TOKEN (root/admin) for provisioning}"
export VAULT_ADDR VAULT_TOKEN

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

ENV_FILE="$(cd "$(dirname "$0")/.." && pwd)/.env"
sed -i '/^VAULT_ROLE_ID=/d;/^VAULT_SECRET_ID=/d' "$ENV_FILE" 2>/dev/null || true
{
  echo "VAULT_ROLE_ID=${ROLE_ID}"
  echo "VAULT_SECRET_ID=${SECRET_ID}"
} >> "$ENV_FILE"
echo "AppRole credentials written to ${ENV_FILE}"
