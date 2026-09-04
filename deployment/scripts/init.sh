#!/usr/bin/env bash
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

# Check keytool
if ! command -v keytool >/dev/null 2>&1; then
    echo "ERROR: Missing required binary: keytool (part of JDK)"
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

if [ ! -f "../suspicious-ui/.env" ]; then
    if [ -f "../suspicious-ui/.env.example" ]; then
        cp ../suspicious-ui/.env.example ../suspicious-ui/.env
        echo "→ UI .env created from .env.example"
    else
        echo "ERROR: Missing both UI .env and .env.example"
    fi
else
    echo "→ UI .env present"
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
    "${CA_PATH}"
    "${CORTEX_PATH}"
    "${CORTEX_PATH}/Cortex-Analyzers-Public/analyzers"
    "${CORTEX_PATH}/Cortex-Analyzers-Public/responders"
    "${CORTEX_PATH}/jobs"
    "${CUSTOM_ANALYZERS_PATH}"
    "${YARA_PATH}"
)

for dir in "${DIRS[@]}"; do
    if [ -d "$dir" ]; then
        perms=$(stat -c '%a' "$dir")
        echo "→ Directory exists: $dir (permissions: $perms)"
    else
        echo "→ Directory missing: $dir"
        echo "Creating directory: $dir"
        mkdir -p "$dir"
        echo "→ Directory created: $dir"
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

# Email Feeder pplication.log
FEEDER_LOG="${FEEDER_PATH}/application.log"
if [ ! -f "$FEEDER_LOG" ]; then
    touch "$FEEDER_LOG"
fi
perm_flog=$(stat -c '%a' "$FEEDER_LOG")
echo "→ Email Feeder log created: $FEEDER_LOG (permissions: $perm_flog)"

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

# # -------------------------------------------------
# # 5. Elasticsearch gc.log
# # -------------------------------------------------
# echo "[5/11] Checking Elasticsearch gc.log..."
# GC_LOG="${ELASTIC_PATH}/logs/gc.log"
# if [ ! -f "$GC_LOG" ]; then
#     touch "$GC_LOG"
# fi
# perm_log=$(stat -c '%a' "$GC_LOG")
# echo "→ Garbage Collector Log exists: $GC_LOG (permissions: $perm_log)"
# echo "→ gc.log OK"

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

# Replace 127.0.0.1:9200 with elasticsearch:9200 in application.conf
if grep -q "127.0.0.1:9200" "$CORTEX_CONF"; then
    sed -i 's/127.0.0.1:9200/elasticsearch:9200/g' "$CORTEX_CONF"
fi

# Wire this repo's custom-analyzer catalog (Analyzers/analyzers.json, mounted
# at /opt/Cortex-Analyzers-AI/analyzers/analyzers.json — see
# CUSTOM_ANALYZERS_PATH) into analyzer.urls. Setting analyzer_urls via the
# cortex compose service's env alone is NOT enough: the entrypoint injects it
# early in the generated config, and this file's own `analyzer { urls = [...] }`
# block appears later via `include` — HOCON's last-assignment-wins means the
# file always overrides the env var. Anchored on the known default line from
# the downloaded sample; a no-op if the array was customized some other way
# (rare — application.conf is gitignored and only ever regenerated here when
# absent) or if this has already run once.
CUSTOM_CATALOG_LINE='"/opt/Cortex-Analyzers-AI/analyzers/analyzers.json"'
if ! grep -qF "$CUSTOM_CATALOG_LINE" "$CORTEX_CONF"; then
    if grep -q 'catalogs.download.strangebee.com/latest/json/analyzers.json' "$CORTEX_CONF"; then
        sed -i "/catalogs.download.strangebee.com\/latest\/json\/analyzers.json\"/a\\    ${CUSTOM_CATALOG_LINE}" "$CORTEX_CONF"
        echo "→ Added custom-analyzer catalog to analyzer.urls"
    else
        echo "→ analyzer.urls doesn't match the expected default — leaving it alone; add ${CUSTOM_CATALOG_LINE} to it by hand if this repo's custom analyzers (AIMailAnalyzer, MailHeaderAnalyzer) need to be visible to Cortex."
    fi
else
    echo "→ Custom-analyzer catalog already wired into analyzer.urls"
fi

# job.directory / job.dockerDirectory: the docker job-runner's nested
# `docker run -v <dir>:/job` needs the HOST path, which only matches
# CORTEX_PATH/jobs because compose mounts it at the identical path inside
# the container. Without this the file relies solely on the `job_directory`
# env var the compose service also sets — belt-and-suspenders, since (as
# above) a later file-level assignment in this same file would silently win
# over that env var if one ever gets added here for another reason.
if ! grep -q '^job {' "$CORTEX_CONF"; then
    cat >> "$CORTEX_CONF" <<EOF

## ── init.sh: local job-runner path (idempotent; safe to hand-edit above this) ──
job {
  directory = "${CORTEX_PATH}/jobs"
  dockerDirectory = \${job.directory}
}
EOF
    echo "→ Added job.directory to application.conf"
else
    echo "→ job.directory already present in application.conf"
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

# The docker.sock mount into cortex is :ro, so the entrypoint's own
# `chown cortex /var/run/docker.sock` no-ops — Cortex (running as uid 1001,
# via compose_apps.yaml's daemon_user) needs to be in the socket's actual
# GID instead, and that GID varies per host (this is NOT the historical
# "uid/gid 1001" assumption — that only ever matched a host that happened
# to have docker's own group at 1001). Auto-detect and keep .env in sync
# so a fresh init doesn't quietly leave Cortex's docker job-runner disabled
# — the only symptom otherwise is "runner didn't generate any output file"
# on every single analyzer job, buried in Cortex's own container logs.
if grep -q '^DOCKER_SOCK_GID=' .env; then
    CURRENT_SOCK_GID=$(grep '^DOCKER_SOCK_GID=' .env | cut -d= -f2)
else
    CURRENT_SOCK_GID=""
fi

if [ "$CURRENT_SOCK_GID" != "$SOCK_GROUP" ]; then
    if grep -q '^DOCKER_SOCK_GID=' .env; then
        sed -i "s/^DOCKER_SOCK_GID=.*/DOCKER_SOCK_GID=${SOCK_GROUP}/" .env
    else
        echo "DOCKER_SOCK_GID=${SOCK_GROUP}" >> .env
    fi
    echo "→ DOCKER_SOCK_GID set to ${SOCK_GROUP} in .env (was '${CURRENT_SOCK_GID:-unset}') — recreate cortex to pick it up if it's already running"
else
    echo "→ DOCKER_SOCK_GID already correct (${SOCK_GROUP})"
fi

# -------------------------------------------------
# 9. Certificates
# -------------------------------------------------
echo "[9/11] Checking certificates..."
CERTFILE="$CA_PATH/certfile.pem"
KEYFILE="$CA_PATH/keyfile.pem"
ROOTCAFILE="$CA_PATH/rootcafile.pem"

# Docker creates a bind-mount source as a directory when it's absent at
# container-create time (see deployment/scripts/check-mounts.sh — same
# footgun, different set of paths). If a service ever mounted these before
# certs existed here, that leaves an empty directory where mv/generation
# below expects a file; clear it so this step can actually run.
for stray in "$CERTFILE" "$KEYFILE" "$ROOTCAFILE" "$CA_PATH/keystore.jks"; do
    if [ -d "$stray" ]; then
        if rmdir "$stray" 2>/dev/null; then
            echo "→ removed stray empty directory (Docker bind-mount artifact): $stray"
        else
            echo "ERROR: $stray is a non-empty directory but a file is expected — inspect and remove it by hand."
        fi
    fi
done

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

echo "Creating Cortex JVM truststore (keystore.jks) from root CA..."
KEYSTORE="$CA_PATH/keystore.jks"
# Cortex's JVM (JAVA_OPTS -Djavax.net.ssl.trustStore) needs a REAL JKS holding
# the root CA. The old code just `touch`ed an empty file, so the truststore
# load failed at boot ("KeyStoreException: Short read of DER length"). Build it
# with keytool. `-s` (non-empty) rather than `-f` so an existing 0-byte
# keystore from an older init is healed on re-run.
if [ "${FORCE_KEYSTORE:-0}" = "1" ] || [ ! -s "$KEYSTORE" ]; then
    rm -f "$KEYSTORE"
    if ! keytool -importcert -noprompt -alias rootca \
            -file "$ROOTCAFILE" -keystore "$KEYSTORE" \
            -storepass changeit -storetype JKS; then
        echo "ERROR: keytool failed to build $KEYSTORE from $ROOTCAFILE" >&2
        exit 1
    fi
    # Never leave a silently-empty keystore behind (the historical failure).
    [ -s "$KEYSTORE" ] || { echo "ERROR: $KEYSTORE is empty after keytool" >&2; exit 1; }
    echo "→ Keystore built: $KEYSTORE"
else
    echo "→ Keystore already present: $KEYSTORE"
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
