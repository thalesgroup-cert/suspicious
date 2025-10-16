#!/bin/sh

# This shell script creates the following artifacts:
#
# - Root Certificate Authority (CA) :
# used to sign server certificates and to allow clients to verify the
# authenticity and integrity of those certificates.
#
# - Public Certificate (server.crt) :
# used by the server to prove its identity to clients and to participate in the
# TLS handshake for secure communication.
#
# - Private Key (server.key) :
# kept secret on the server; used to decrypt handshake material sent by clients
# and to sign messages during TLS handshake.
#
# Note: Actual email (IMAP/SMTP) traffic is encrypted with a symmetric session
# key negotiated during the TLS handshake. The certificate and private key are
# only involved in the handshake and authentication process.
#
# Usage :
# ./openssl-certificates-generator ENV_NAME [--force|-f]
#
# Output :
# certificates/ENV_NAME
# ├── ca.cert.pem : config.mail-connectors.imaps.imaps-ENV_NAME.rootcafile
# ├── ca.cert.srl
# ├── ca.key.pem
# ├── client.crt.pem : config.mail-connectors.imaps.imaps-ENV_NAME.cafile
# ├── client.csr.pem
# ├── client.key.pem : config.mail-connectors.imaps.imaps-ENV_NAME.keyfile
# ├── server.cert.pem
# ├── server.csr.pem
# └── server.key.pem

OUTPUT_DIR="./certificates"
SERVER_DAYS_VALID=825
CA_DAYS_VALID=3650
CERT_SUBJECT="/C=COUNTRY/ST=STATE/L=CITY/O=ORGANIZATION/OU=Suspicious"
ROOT_CERTIFICATE_AUTHORITY="SuspiciousRootCA"
IMAP_SERVER_DNS="localhost" # mail.example.com
IMAP_SERVER_IP="127.0.0.1"

generate_ssl_context() {
    # Arguments
    local ENV="$1"
    local FORCE="$2"

    # Base output directory
    local OUTPUT_DIR="./certificates"
    local ENV_DIR="$OUTPUT_DIR/$ENV"

    # Make paths for all artifacts
    local ROOT_CA_KEY="$ENV_DIR/ca.key.pem"
    local ROOT_CA_CERT="$ENV_DIR/ca.cert.pem"
    local ROOT_CA_SERIAL="$ENV_DIR/ca.cert.srl"

    local SERVER_KEY="$ENV_DIR/server.key.pem"
    local SERVER_CSR="$ENV_DIR/server.csr.pem"
    local SERVER_CERT="$ENV_DIR/server.cert.pem"

    local CLIENT_KEY="$ENV_DIR/client.key.pem"
    local CLIENT_CSR="$ENV_DIR/client.csr.pem"
    local CLIENT_CERT="$ENV_DIR/client.crt.pem"

    # Check if output directory exists
    if [ -d "$ENV_DIR" ]; then
        if [ "$FORCE" != "1" ]; then
            echo "Error: Directory $ENV_DIR already exists. Use --force to overwrite." >&2
            exit 1
        else
            echo "Warning: Directory $ENV_DIR already exists. Files may be overwritten." >&2
        fi
    fi

    mkdir -p "$ENV_DIR"

    # ----------------------
    # Generate Root CA
    # ----------------------
    openssl genrsa -out "$ROOT_CA_KEY" 4096
    openssl req -x509 -new -nodes -key "$ROOT_CA_KEY" \
        -sha256 -days "$CA_DAYS_VALID" \
        -out "$ROOT_CA_CERT" \
        -subj "$CERT_SUBJECT/CN=$ROOT_CERTIFICATE_AUTHORITY"

    # ----------------------
    # Generate Server Certificate
    # ----------------------
    openssl genrsa -out "$SERVER_KEY" 2048
    openssl req -new -key "$SERVER_KEY" -out "$SERVER_CSR" \
        -subj "$CERT_SUBJECT/CN=server.$ENV.local"

    openssl x509 -req -in "$SERVER_CSR" -CA "$ROOT_CA_CERT" -CAkey "$ROOT_CA_KEY" \
        -CAcreateserial -out "$SERVER_CERT" -days "$SERVER_DAYS_VALID" -sha256

    openssl genrsa -out "$CLIENT_KEY" 2048
    openssl req -new -key "$CLIENT_KEY" -out "$CLIENT_CSR" \
        -subj "${CERT_SUBJECT}/CN=client.$ENV.local"

    openssl x509 -req -in "$CLIENT_CSR" -CA "$ROOT_CA_CERT" -CAkey "$ROOT_CA_KEY" \
        -CAcreateserial -out "$CLIENT_CERT" -days "$SERVER_DAYS_VALID" -sha256

    echo "Certificates and keys generated in $ENV_DIR :"
    echo "  Root CA     : $ROOT_CA_CERT"
    echo "  Server cert : $SERVER_CERT"
    echo "  Server key  : $SERVER_KEY"
    echo "  Client cert : $CLIENT_CERT"
    echo "  Client key  : $CLIENT_KEY"
}


main() {
    # ----------------------
    # CLI parsing
    # ----------------------
    if [ "$#" -lt 1 ]; then
        echo "Usage: $0 ENV_NAME [--force|-f]" >&2
        exit 1
    fi

    ENV_NAME="$1"
    FORCE_FLAG=0

    if [ "$#" -eq 2 ]; then
        case "$2" in
            --force|-f) FORCE_FLAG=1 ;;
            *) echo "Unknown option: $2" >&2; exit 1 ;;
        esac
    fi

    generate_ssl_context "$ENV_NAME" "$FORCE_FLAG"
}

main $@
