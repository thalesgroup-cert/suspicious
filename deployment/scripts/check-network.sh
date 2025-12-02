#!/usr/bin/env bash
set -Eeuo pipefail
source ../.env

if ! docker network inspect "$NETWORK_NAME" &>/dev/null; then
    log "Network $NETWORK_NAME not found. Creating it..."
    docker network create --subnet=$NETWORK_SUBNET --gateway=$NETWORK_GATEWAY --ip-range=$NETWORK_IP_RANGE "$NETWORK_NAME"
    log "Network $NETWORK_NAME created successfully."
else
    log "Network $NETWORK_NAME already exists."
fi