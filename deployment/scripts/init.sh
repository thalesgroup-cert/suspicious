#!/usr/bin/env sh
set -eu

echo "============================================"
echo "      SUSPICIOUS – CHECKLIST"
echo "============================================"

# -------------------------------------------------
# 1. Required binaries
# -------------------------------------------------
echo "[1/11] Checking required binaries..."

# Check for docker binary
if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: Missing required binary: docker"
fi

# Check that docker supports the compose subcommand
if ! docker compose version >/dev/null 2>&1; then
    echo "ERROR: Docker Compose is not available (docker compose subcommand required)"
fi

# Check curl
if ! command -v curl >/dev/null 2>&1; then
    echo "ERROR: Missing required binary: curl"
fi

echo "→ OK"

# -------------------------------------------------
# 2. Ensure .env exists
# -------------------------------------------------
echo "[2/11] Checking .env..."

if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo "→ .env created from .env.example"
    else
        echo "ERROR: Missing both .env and .env.example"
    fi
else
    echo "→ .env present"
fi

# Load environment variables
set -a
. ./.env
set +a

# -------------------------------------------------
# 3. Directory structure check
# -------------------------------------------------
echo "[3/11] Checking directory structure..."

DIRS=(
    "${ELASTIC_PATH}"
    "${ELASTIC_PATH}/logs"
    "${DB_SUSPICIOUS_PATH}"
    "${MINIO_PATH}"
    "${CA_PATH}"
    "${CORTEX_PATH}"
    "${CORTEX_PATH}/jobs"
    "${CORTEX_PATH}/Cortex-Analyzers-Public/analyzers"
    "${CORTEX_PATH}/Cortex-Analyzers-Public/responders"
    "${AIANALYZER_PATH}"
    "${YARA_PATH}"
)

for dir in "${DIRS[@]}"; do
    if [ -d "$dir" ]; then
        perms=$(stat -c '%a' "$dir")
        echo "→ Directory exists: $dir (permissions: $perms)"
    else
        echo "→ Directory missing: $dir"
    fi
done

echo "→ Directory structure check complete"

# -------------------------------------------------
# 4. Check settings.json and Email Feeder config.json
# -------------------------------------------------
echo "[4/11] Checking application configuration..."

# Suspicious settings.json
if [ ! -f "${SUSPICIOUS_PATH}/settings.json" ]; then
    if [ -f "${SUSPICIOUS_PATH}/settings-sample.json" ]; then
        cp "${SUSPICIOUS_PATH}/settings-sample.json" "${SUSPICIOUS_PATH}/settings.json"
        echo "→ settings.json created from sample"
    else
        echo "ERROR: Missing both settings.json and settings-sample.json"
    fi
else
    echo "→ settings.json present"
fi

# Email Feeder config.json
if [ ! -f "${FEEDER_PATH}/config.json" ]; then
    if [ -f "${FEEDER_PATH}/config-sample.json" ]; then
        cp "${FEEDER_PATH}/config-sample.json" "${FEEDER_PATH}/config.json"
        echo "→ config.json created from sample"
    else
        echo "ERROR: Missing both config.json and config-sample.json"
    fi
else
    echo "→ Email Feeder config.json present"
fi

# Traefik TLS file
TLS_FILE="${TRAEFIK_PATH}/dynamic/tls.yaml"
if [ -f "$TLS_FILE" ]; then
    if [ -n "${DOMAIN_CORP:-}" ]; then
        TMP_FILE="${TLS_FILE}.tmp"
        sed "s/Host(\`suspicious\`)/Host(\`${DOMAIN_CORP}\`)/" "$TLS_FILE" > "$TMP_FILE"
        mv "$TMP_FILE" "$TLS_FILE"
        echo "→ tls.yaml updated with DOMAIN_CORP=${DOMAIN_CORP}"
    else
        echo "→ DOMAIN_CORP not set; tls.yaml not updated"
    fi
else
    echo "→ tls.yaml not present in Traefik dynamic path"
fi

# -------------------------------------------------
# 5. Elasticsearch gc.log
# -------------------------------------------------
echo "[5/11] Checking Elasticsearch gc.log..."
GC_LOG="${ELASTIC_PATH}/logs/gc.log"
if [ ! -f "$GC_LOG" ]; then
    touch "$GC_LOG"
fi
perm_log=$(stat -c '%a' "$GC_LOG")
echo "→ Garbage Collector Log exists: $GC_LOG (permissions: $perm_log)"
echo "→ gc.log OK"

# -------------------------------------------------
# 6. Cortex application.conf
# -------------------------------------------------
echo "[6/11] Ensuring Cortex configuration..."
CORTEX_CONF="${CORTEX_PATH}/application.conf"
CORTEX_SAMPLE_URL="https://raw.githubusercontent.com/TheHive-Project/Cortex/master/conf/application.sample"
CORTEX_LOG="${CORTEX_PATH}/application-cortex.log"

if [ ! -f "$CORTEX_CONF" ]; then
    echo "→ application.conf missing, downloading from official Cortex repository..."
    curl -fsSL "$CORTEX_SAMPLE_URL" -o "$CORTEX_CONF" || {
        echo "ERROR: Failed to download Cortex application.sample"
    }
else
    echo "→ application.conf exists — not overwritten"
fi

[ ! -f "$CORTEX_LOG" ] && touch "$CORTEX_LOG"
perm_clog=$(stat -c '%a' "$CORTEX_LOG")

perm_cconf=$(stat -c '%a' "$CORTEX_CONF")

echo "→ Cortex Log created: $CORTEX_LOG  (permissions: $perm_clog)"
echo "→ Cortex Conf created: $CORTEX_CONF (permissions: $perm_cconf)"
echo "→ Cortex configuration OK"

# -------------------------------------------------
# 7. Cortex docker config.json
# -------------------------------------------------
echo "[7/11] Checking Cortex Docker config..."
[ ! -d "$DOCKER_PATH" ] && mkdir -p "$DOCKER_PATH"
[ ! -f "${DOCKER_PATH}/config.json" ] && echo '{ "auths": {} }' > "${DOCKER_PATH}/config.json"
echo "→ Docker config.json OK"

# -------------------------------------------------
# 8. Cortex user and Docker socket
# -------------------------------------------------
echo "[8/11] Checking Cortex Docker socket permissions..."
DOCKER_SOCK="/var/run/docker.sock"

[ ! -S "$DOCKER_SOCK" ] && {
    echo "ERROR: Docker socket not found at $DOCKER_SOCK"
}

SOCK_OWNER=$(stat -c '%u' "$DOCKER_SOCK")
SOCK_GROUP=$(stat -c '%g' "$DOCKER_SOCK")
SOCK_MODE=$(stat -c '%a' "$DOCKER_SOCK")
echo "→ Docker socket owner: $SOCK_OWNER:$SOCK_GROUP (mode $SOCK_MODE)"

if [ "$SOCK_OWNER" -eq 1001 ] || [ "$SOCK_GROUP" -eq 1001 ]; then
    echo "→ Permissions OK for Cortex (uid/gid 1001)"
else
    echo "WARNING: Docker socket not owned by uid/gid 1001"
    echo "Cortex may fail unless permissions are adjusted"
fi

# -------------------------------------------------
# 9. Certificates
# -------------------------------------------------
echo "[9/11] Checking certificates..."
CERTFILE="$CA_PATH/certfile.pem"
KEYFILE="$CA_PATH/keyfile.pem"
ROOTCAFILE="$CA_PATH/rootcafile.pem"

if [ ! -f "$CERTFILE" ] || [ ! -f "$KEYFILE" ] || [ ! -f "$ROOTCAFILE" ]; then
    echo "→ Missing certificates, generating..."
    ./scripts/openssl-certificates-generator.sh default --force
    mv ./certificates/default/certfile.pem "$CERTFILE"
    mv ./certificates/default/keyfile.pem "$KEYFILE"
    mv ./certificates/default/rootcafile.pem "$ROOTCAFILE"
    echo "→ Certificates generated in $CA_PATH"
else
    echo "→ Certificates already present"
fi

# -------------------------------------------------
# 10. Cortex catalogs
# -------------------------------------------------
echo "[10/11] Downloading Cortex catalogs..."
ANALYZERS_URL="https://catalogs.download.strangebee.com/latest/json/analyzers.json"
RESPONDERS_URL="https://catalogs.download.strangebee.com/latest/json/responders.json"
ANALYZERS_DEST="${CORTEX_PATH}/Cortex-Analyzers-Public/analyzers/analyzers.json"
RESPONDERS_DEST="${CORTEX_PATH}/Cortex-Analyzers-Public/responders/responders.json"

curl -fsSL "$ANALYZERS_URL" -o "$ANALYZERS_DEST"
curl -fsSL "$RESPONDERS_URL" -o "$RESPONDERS_DEST"
echo "→ Cortex catalogs OK"

# -------------------------------------------------
# 11. Completion
# -------------------------------------------------
echo "============================================"
echo "    CHECKLIST COMPLETED"
echo "    All required components are in place."
echo "    You can now modify:"
echo "        - ${SUSPICIOUS_PATH}/settings.json"
echo "        - ${FEEDER_PATH}/config.json"
echo "        - ${CORTEX_PATH}/application.conf"
echo "        - ${TRAEFIK_PATH}/dynamic/tls.yaml"
echo "============================================"
