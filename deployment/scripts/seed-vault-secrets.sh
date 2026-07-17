#!/usr/bin/env bash
# Seed Suspicious secrets into Vault (KV v2 at suspicious/<dotted-key>, field
# "value"). Vault runs as a Docker Compose service, so vault commands execute
# inside that container. Requires VAULT_TOKEN. Secret values come from the
# operator's environment (export them before running) — never from a committed
# file. Unset optional secrets are written empty.
set -euo pipefail
: "${VAULT_TOKEN:?set VAULT_TOKEN (root/admin) for seeding}"
export VAULT_TOKEN

cd "$(cd "$(dirname "$0")/.." && pwd)"   # so `docker compose` resolves .env + COMPOSE_FILE

VAULT_SVC="${VAULT_SVC:-vault}"
# Run the vault CLI inside the running Vault container (no host CLI required).
vault() {
  docker compose --env-file .env exec -T \
    -e VAULT_TOKEN -e VAULT_ADDR=http://127.0.0.1:8200 \
    "$VAULT_SVC" vault "$@"
}

put() { vault kv put "suspicious/$1" value="$2" >/dev/null && echo "  wrote suspicious/$1"; }

echo "Seeding secrets into Vault ..."
put app.secret_key                                "${SECRET_KEY:?export SECRET_KEY}"
put database.password                             "${DB_PASSWORD:?export DB_PASSWORD}"
put integrations.cortex.api_key                   "${CORTEX_API_KEY:?export CORTEX_API_KEY}"
put integrations.cortex.webhook_secret            "${CORTEX_WEBHOOK_SECRET:?export CORTEX_WEBHOOK_SECRET}"
put storage.s3.secret_key                         "${S3_SECRET_KEY:?export S3_SECRET_KEY}"
put integrations.thehive.api_key                  "${THEHIVE_API_KEY:-}"
put integrations.misp.instances.primary.api_key   "${MISP_PRIMARY_API_KEY:-}"
put integrations.misp.instances.secondary.api_key "${MISP_SECONDARY_API_KEY:-}"
put integrations.watcher.api_key                  "${WATCHER_API_KEY:-}"
put authentication.ldap.bind_password             "${LDAP_BIND_PASSWORD:-}"
put authentication.oidc.client_secret             "${OIDC_CLIENT_SECRET:-}"
put email.smtp.password                           "${SMTP_PASSWORD:-}"
echo "Done."
