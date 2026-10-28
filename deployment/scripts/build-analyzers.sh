#!/usr/bin/env bash
# build-analyzers.sh — Build the images Cortex runs the custom analyzers from.
#
# analyzers.json points at aimailanalyzer:local and mailheaderanalyzer:local,
# which no registry serves, so a deploy that does not rebuild them keeps running
# whatever image was built last (for AI_Mail_Analyzer, possibly the old
# self-contained analyzer that never calls the inference server).
set -euo pipefail
source .env

SRC="${CUSTOM_ANALYZERS_PATH:-../Analyzers}"
PROXY_ARGS=(--build-arg "HTTP_PROXY=${HTTP_PROXY:-}" --build-arg "HTTPS_PROXY=${HTTPS_PROXY:-}")

docker build "${PROXY_ARGS[@]}" -t aimailanalyzer:local "${SRC}/AIMailAnalyzer"
docker build "${PROXY_ARGS[@]}" -t mailheaderanalyzer:local "${SRC}/MailHeaderAnalyzer"
