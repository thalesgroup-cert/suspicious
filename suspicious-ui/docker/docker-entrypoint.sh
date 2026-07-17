#!/bin/sh
# nginx:alpine runs every /docker-entrypoint.d/*.sh before starting nginx.
# This drop-in regenerates the runtime env config the SPA reads
# (window.__ENV__ in /env-config.js) from the container's environment, so a
# single image is configured per deployment — set VITE_* in compose, no rebuild.
set -eu

CONFIG="/usr/share/nginx/html/env-config.js"

# JSON-string-escape a value (backslash + double-quote).
esc() {
  printf '%s' "${1:-}" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

{
  printf 'window.__ENV__ = {\n'
  printf '  "VITE_API_BASE": "%s",\n'            "$(esc "${VITE_API_BASE:-}")"
  printf '  "VITE_FAVICON": "%s",\n'             "$(esc "${VITE_FAVICON:-}")"
  printf '  "VITE_COMPANY_NAME": "%s",\n'        "$(esc "${VITE_COMPANY_NAME:-}")"
  printf '  "VITE_COMPANY_LINK": "%s",\n'        "$(esc "${VITE_COMPANY_LINK:-}")"
  printf '  "VITE_COMPANY_LOGO_BASE64": "%s",\n' "$(esc "${VITE_COMPANY_LOGO_BASE64:-}")"
  printf '  "VITE_COMPANY_LOGO_URL": "%s",\n'    "$(esc "${VITE_COMPANY_LOGO_URL:-}")"
  printf '  "VITE_SUPPORT_EMAIL": "%s",\n'       "$(esc "${VITE_SUPPORT_EMAIL:-}")"
  printf '  "VITE_SUSPICIOUS_EMAIL": "%s"\n'     "$(esc "${VITE_SUSPICIOUS_EMAIL:-}")"
  printf '};\n'
} > "$CONFIG"
