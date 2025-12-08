#!/usr/bin/env sh
set -eu

echo "============================================"
echo "      SUSPICIOUS – CHECKLIST"
echo "============================================"

# -------------------------------------------------
# 1. Required binaries
# -------------------------------------------------
echo "[1/11] Checking required binaries..."

REQUIRED_CMDS="docker
docker compose
curl"
for cmd in $REQUIRED_CMDS; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: Missing required binary: $cmd"
        exit 1
    fi
done
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
        exit 1
    fi
else
    echo "→ .env present"
fi



# -------------------------------------------------
# Load variables for later steps
# -------------------------------------------------
set -a
. ./.env
set +a

# -------------------------------------------------
# 3. Base directory structure
# -------------------------------------------------
echo "[3/11] Ensuring directory structure..."

# Directories and their recommended permissions
declare -A DIRS_PERMS=(
    ["${ELASTIC_PATH}"]=755
    ["${ELASTIC_PATH}/logs"]=755
    ["${DB_SUSPICIOUS_PATH}"]=755
    ["${CORTEX_PATH}"]=755
    ["${CORTEX_PATH}/jobs"]=755
    ["${CORTEX_PATH}/Cortex-Analyzers-Public/analyzers"]=755
    ["${CORTEX_PATH}/Cortex-Analyzers-Public/responders"]=755
    ["${AIANALYZER_PATH}"]=755
    ["${YARA_PATH}"]=755
)

for dir in "${!DIRS_PERMS[@]}"; do
    mkdir -p "$dir"
    chmod "${DIRS_PERMS[$dir]}" "$dir"
done

echo "→ Directories created with proper permissions"


# -------------------------------------------------
# 5. Check if settings.json and config.json exist
# -------------------------------------------------

echo "[5/11] Checking settings.json and config.json..."


EMAIL_FEEDER_PATH="${FEEDER_PATH}"

if [ ! -f "${SUSPICIOUS_PATH}/settings.json" ]; then
    if [ -f "${SUSPICIOUS_PATH}/settings-sample.json" ]; then
        cp "${SUSPICIOUS_PATH}/settings-sample.json" "${SUSPICIOUS_PATH}/settings.json"
        echo "→ settings.json created from settings-sample.json"
    else
        echo "ERROR: Missing both settings.json and settings-sample.json"
        exit 1
    fi
else
    echo "→ settings.json present"
fi

if [ ! -f "${EMAIL_FEEDER_PATH}/config.json" ]; then
    if [ -f "${EMAIL_FEEDER_PATH}/config-sample.json" ]; then
        cp "${EMAIL_FEEDER_PATH}/config-sample.json" "${EMAIL_FEEDER_PATH}/config.json"
        echo "→ config.json created from config-sample.json"
    else
        echo "ERROR: Missing both config.json and config-sample.json in Email Feeder path"
        exit 1
    fi
else
    echo "→ config.json present in Email Feeder path"
fi


# -------------------------------------------------
# 6. Elasticsearch gc.log
# -------------------------------------------------
echo "[6/11] Checking Elasticsearch gc.log..."

if [ ! -f "elasticsearch/logs/gc.log" ]; then
    touch elasticsearch/logs/gc.log
fi
chmod 644 elasticsearch/logs/gc.log
echo "→ gc.log OK"


# -------------------------------------------------
# 7. Cortex application.conf from official repo
# -------------------------------------------------
echo "[7/11] Ensuring Cortex application.conf (from upstream)..."

CORTEX_CONF="${CORTEX_PATH}/application.conf"
CORTEX_SAMPLE_URL="https://raw.githubusercontent.com/TheHive-Project/Cortex/master/conf/application.sample"
CORTEX_LOG="${CORTEX_PATH}/application-cortex.log"

mkdir -p "${CORTEX_PATH}"

if [ ! -f "${CORTEX_CONF}" ]; then
    echo "→ application.conf missing, downloading application.sample from official Cortex repository..."
    if curl -fsSL "${CORTEX_SAMPLE_URL}" -o "${CORTEX_CONF}"; then
        echo "→ application.conf created from upstream application.sample"
    else
        echo "ERROR: Failed to download application.sample from upstream."
        exit 1
    fi
else
    echo "→ application.conf already exists — not overwritten"
fi

# Create log file if missing
if [ ! -f "${CORTEX_LOG}" ]; then
    echo "→ creating application-cortex.log file: ${CORTEX_LOG}"
    touch "${CORTEX_LOG}"
else
    echo "WARNING: Cortex log file already exists."
fi

chmod 640 "${CORTEX_CONF}"
echo "→ application.conf OK"
chmod 664 "${CORTEX_LOG}"
echo "→ application-cortex.log OK"


# -------------------------------------------------
# 8. Cortex docker config.json
# -------------------------------------------------
echo "[8/11] Checking Cortex docker config.json..."

if [ ! -d "$DOCKER_PATH" ]; then
    mkdir -p "$DOCKER_PATH"
fi

if [ ! -f "${DOCKER_PATH}/config.json" ]; then
    echo '{ "auths": {} }' > "${DOCKER_PATH}/config.json"
fi

chmod 600 "${DOCKER_PATH}/config.json"
echo "→ config.json OK"


# -------------------------------------------------
# 9. Cortex user 1001:1001 and Docker socket access
# -------------------------------------------------
echo "[9/11] Checking Cortex user and Docker socket permissions..."

# Check that user and group 1001 exist
if ! id -u 1001 >/dev/null 2>&1; then
    echo "WARNING: No system user with UID 1001 found."
    echo "→ Cortex runs inside Docker using uid 1001, host user is not strictly required."
else
    echo "→ UID 1001 exists on host"
fi

if ! getent group 1001 >/dev/null 2>&1; then
    echo "WARNING: No system group with GID 1001 found."
else
    echo "→ GID 1001 exists on host"
fi

# Check docker socket
DOCKER_SOCK="/var/run/docker.sock"

if [ ! -S "${DOCKER_SOCK}" ]; then
    echo "ERROR: Docker socket not found at ${DOCKER_SOCK}"
    exit 1
fi

echo "→ Docker socket exists"

# Check if uid 1001 is allowed to access it
SOCK_OWNER="$(stat -c '%u' ${DOCKER_SOCK})"
SOCK_GROUP="$(stat -c '%g' ${DOCKER_SOCK})"
SOCK_MODE="$(stat -c '%a' ${DOCKER_SOCK})"

echo "→ Docker socket owner: ${SOCK_OWNER}:${SOCK_GROUP} (mode ${SOCK_MODE})"

if [ "${SOCK_OWNER}" -eq 1001 ] || [ "${SOCK_GROUP}" -eq 1001 ]; then
    echo "→ Permissions OK for Cortex (uid 1001)"
else
    echo "WARNING: Docker socket is not owned by uid/gid 1001"
    echo "Cortex may fail to run analyzers unless permissions are adjusted."

    # Optional auto-fix (safe because socket is recreated at Docker restart)
    echo "→ Setting group ownership to 1001 for Docker socket"
    chgrp 1001 "${DOCKER_SOCK}" || echo "WARNING: Failed to change group ownership"

    echo "→ Applying group read/write permissions"
    chmod g+rw "${DOCKER_SOCK}" || echo "WARNING: Failed to adjust permissions"
fi

echo "→ Cortex Docker socket access check complete"


# -------------------------------------------------
# 10. Certificates
# -------------------------------------------------
echo "[10/11] Checking certificates..."

mkdir -p "$CA_PATH"

# Check if required certificate files exist
CERTFILE="$CA_PATH/certfile.pem"
KEYFILE="$CA_PATH/keyfile.pem"
ROOTCAFILE="$CA_PATH/rootcafile.pem"

if [ ! -f "$CERTFILE" ] || [ ! -f "$KEYFILE" ] || [ ! -f "$ROOTCAFILE" ]; then
    echo "→ Missing certificates, generating via openssl-certificates-generator.sh..."
    
    # Call generator script for default environment "default"
    ./scripts/openssl-certificates-generator.sh default --force

    # Move generated files to CA_PATH
    mv ./certificates/default/certfile.pem "$CERTFILE"
    mv ./certificates/default/keyfile.pem "$KEYFILE"
    mv ./certificates/default/rootcafile.pem "$ROOTCAFILE"

    echo "→ Certificates generated in $CA_PATH"
else
    echo "→ Certificates already present, skipping generation"
fi


# -------------------------------------------------
# 11. Cortex catalogs (analyzers.json + responders.json)
# -------------------------------------------------
echo "[11/11] Downloading Cortex catalogs..."

ANALYZERS_URL="https://catalogs.download.strangebee.com/latest/json/analyzers.json"
RESPONDERS_URL="https://catalogs.download.strangebee.com/latest/json/responders.json"

ANALYZERS_DEST="${CORTEX_PATH}/Cortex-Analyzers-Public/analyzers/analyzers.json"
RESPONDERS_DEST="${CORTEX_PATH}/Cortex-Analyzers-Public/responders/responders.json"

echo "→ Downloading analyzers.json..."
curl -fsSL "$ANALYZERS_URL" -o "$ANALYZERS_DEST"

echo "→ Downloading responders.json..."
curl -fsSL "$RESPONDERS_URL" -o "$RESPONDERS_DEST"

chmod 644 "$ANALYZERS_DEST" "$RESPONDERS_DEST"

echo "→ Cortex catalogs OK"


# -------------------------------------------------
# Final
# -------------------------------------------------
echo "============================================"
echo "    CHECKLIST COMPLETED                     "
echo "    All required components are in place.   "
echo "    You can now proceed to modify           "
echo "        - ${SUSPICIOUS_PATH}/settings.json  "
echo "        - ${FEEDER_PATH}/config.json        "
echo "        - ${CORTEX_PATH}/application.conf   "
echo "============================================"
