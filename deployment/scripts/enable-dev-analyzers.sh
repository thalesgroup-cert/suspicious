#!/usr/bin/env bash
set -Eeuo pipefail
source .env

# Enable a set of Cortex analyzers that need NO API key / external account, so
# a dev stack produces real analyzer output end-to-end. Idempotent: re-enabling
# an already-enabled analyzer is a no-op 201.
#
# Cortex persists these in its Elasticsearch index — they survive restarts as
# long as the ES volume does; re-run this after a fresh `make init` / volume
# wipe. sync_cortex (the Suspicious side) does NOT drive dispatch — dispatch
# asks Cortex live via get_by_type — so this is all that's needed.
#
#   cd deployment && ./scripts/enable-dev-analyzers.sh

CORTEX_URL="${CORTEX_LOCAL_URL:-http://localhost:${CORTEX_PORT:-9001}}"
KEY=$(python3 -c "import json,sys; print(json.load(open('../Suspicious/settings.json'))['integrations']['cortex']['api_key'])")

# analyzerDefinitionId : keyless, returns useful data for the listed dtypes
ANALYZERS=(
  DShield_lookup_1_0                        # ip   — SANS ISC reputation
  # Cyberprotect_ThreatScore_3_0 — removed: public API is IP-filtered, every
  #   job returns 403 "Blocked by IP filtering" -> no data. Needs a licensed
  #   account. score_process has a bespoke parser (contrib/cyberprotect.py) so
  #   a deployment with API access can re-add this line and get it scored.
  CyberCrime-Tracker_1_0                    # ip/domain/url — C2 tracker
  SpamhausDBL_1_0                           # domain — Spamhaus DBL
  StopForumSpam_1_0                         # ip/mail — abuse reputation
  TeamCymruMHR_1_0                          # hash — malware hash registry
  CIRCLHashlookup_1_1                       # hash — known-file lookup
  ClamAV_FileInfo_1_1                       # file — ClamAV scan
  ThreatMiner_1_0                           # ip/domain — OSINT (flaky upstream)
  Crt_sh_Transparency_Logs_1_0              # domain — cert transparency
  GoogleDNS_resolve_1_0_0                   # domain/ip — DoH resolve
  Mnemonic_pDNS_Public_3_0                  # ip/domain — passive DNS
  UnshortenLink_1_2                         # url — follow redirects
  MSDefenderOffice365_SafeLinksDecoder_1_0  # url — decode ATP SafeLinks
  DomainMailSPFDMARC_1_2                    # domain — SPF/DMARC posture
  QrDecode_1_0                              # file — decode QR codes
  Lookyloo_Screenshot_1_0                   # url/domain/fqdn/ip — THA-CERT analyzer; screenshots via a Lookyloo instance (public CIRCL by default)
)

# Public CIRCL Lookyloo instance by default; override for a private prod instance.
# Matches the analyzer manifest default (Lookyloo_instance, trailing slash).
LOOKYLOO_URL="${LOOKYLOO_URL:-https://lookyloo.circl.lu/}"

cfg='{"auto_extract_artifacts":false,"check_tlp":false,"max_tlp":2,"check_pap":false,"max_pap":2}'
ok=0 already=0 err=0
for a in "${ANALYZERS[@]}"; do
  acfg=$cfg
  if [[ $a == Lookyloo_Screenshot* ]]; then
    # config key from the THA-CERT Lookyloo_Screenshot manifest: "Lookyloo_instance"
    # (a URL; the analyzer defaults it to the public CIRCL instance if omitted).
    acfg="${cfg%\}},\"Lookyloo_instance\":\"$LOOKYLOO_URL\"}"
  fi
  body=$(curl -s --noproxy '*' -w '\n%{http_code}' -X POST \
    -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
    "$CORTEX_URL/api/organization/analyzer/$a" \
    -d "{\"name\":\"$a\",\"configuration\":$acfg,\"rate\":null,\"rateUnit\":null,\"jobCache\":null}")
  code=${body##*$'\n'}
  case "$code" in
    201)                                  echo "→ enabled          $a"; ok=$((ok+1));;
    *ConflictError*|*already\ exists*)     echo "→ already enabled  $a"; already=$((already+1));;
    *) [ "$code" = 400 ] && grep -q Conflict <<<"$body" \
         && { echo "→ already enabled  $a"; already=$((already+1)); } \
         || { echo "→ ERROR $code       $a"; err=$((err+1)); };;
  esac
done
echo "enabled $ok, already $already, errors $err"
echo "current: $(curl -s --noproxy '*' -H "Authorization: Bearer $KEY" "$CORTEX_URL/api/analyzer?range=all" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)),"analyzers active")')"
