#!/bin/bash
# run_prod_retrain_cycle.sh — Production retrain cycle: fetch real
# "challenged" mail via IMAP, retrain the 5 sub-models, and promote any
# model whose F1 does NOT regress vs the last promoted baseline.
#
# Unlike run_monthly_cycle.sh (dev-only demo/simulator - see its own header),
# this script:
#   - does NOT run simulate_mail_arrival.py - no synthetic mail is injected,
#     only what analysts actually triaged into the IMAP taxonomy folders.
#   - does NOT pass --force to promote.py - a per-model F1 regression still
#     blocks THAT model's promotion (other models still go through).
#   - maintains data_base_results/ itself after a successful promotion.
#     promote.py only PRINTS a reminder to copy the results dir there by
#     hand ("Pensez à copier ... pour que ce run serve de baseline") - a
#     cron job can't act on a printed reminder, so this script does it, or
#     every future run would have no baseline and the F1 guard would be a
#     no-op forever.
#   - does NOT create/expand the golden set (golden_set.py --create/--expand)
#     - that stays a deliberate manual step, see golden_set.py's own header.
#
# Cadence is config-driven rather than baked into the crontab line: point
# cron at this script often (e.g. every 5 min) and it no-ops unless
# RETRAIN_INTERVAL_MINUTES (.env, default 60) minutes have passed since the
# last COMPLETED cycle (tracked in .retrain_state/last_run). Change the
# cadence by editing .env - no `crontab -e` needed again afterwards.
#
# Usage (crontab -e):
#   */5 * * * * cd "/path/to/Analyzers/AIMailAnalyzer/retrain model monthly" && ./run_prod_retrain_cycle.sh >> run_prod_retrain_cycle.log 2>&1
#
# Manual one-off run, ignoring the interval check:
#   ./run_prod_retrain_cycle.sh --force-run

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

FORCE_RUN=false
[[ "${1:-}" == "--force-run" ]] && FORCE_RUN=true

# ---- config-driven cadence --------------------------------------------------
set -a; [[ -f .env ]] && source .env; set +a
RETRAIN_INTERVAL_MINUTES="${RETRAIN_INTERVAL_MINUTES:-60}"

STATE_DIR=".retrain_state"
mkdir -p "$STATE_DIR"
LAST_RUN_FILE="$STATE_DIR/last_run"

if ! $FORCE_RUN && [[ -f "$LAST_RUN_FILE" ]]; then
  last_run=$(cat "$LAST_RUN_FILE")
  elapsed_min=$(( ($(date +%s) - last_run) / 60 ))
  if (( elapsed_min < RETRAIN_INTERVAL_MINUTES )); then
    exit 0   # not due yet - this fires every few minutes by design, stay quiet
  fi
fi

# ---- overlap guard -----------------------------------------------------------
# Separate lockfile from run_monthly_cycle.sh's (aimailanalyzer_retrain_cycle.lock)
# so the dev simulator and this prod script can never silently block each
# other if both somehow end up scheduled on the same host.
LOCKFILE="/tmp/aimailanalyzer_prod_retrain_cycle.lock"
exec 200>"$LOCKFILE"
if ! flock -n 200; then
  echo "$(date '+%Y-%m-%d %H:%M:%S') : another prod retrain cycle is already running (lock: $LOCKFILE) - skipping." >&2
  exit 0
fi

HF_CACHE="${HF_CACHE:-/home/cert/hf_cache}"
TRAINER_IMAGE="retrain-trainer:latest"
VECTORIZER="${VECTORIZER_PATH:-sentence-transformers/paraphrase-multilingual-mpnet-base-v2}"

# Must mount the whole AIMailAnalyzer/ parent, not just this subfolder - see
# run_monthly_cycle.sh's own comment on this (Re_Train_Model/utils.py imports
# the real production ResNetMLP.py/mail_analysis.py via a "../.." sys.path hack).
AIMAILANALYZER_DIR="$(cd .. && pwd)"

run_trainer_shell() {
  docker run --rm --network host \
    -v "$AIMAILANALYZER_DIR:/aimailanalyzer" \
    -w "/aimailanalyzer/retrain model monthly" \
    -v "$HF_CACHE:/root/.cache/huggingface" \
    -e HF_HOME=/root/.cache/huggingface \
    -e VECTORIZER_PATH="$VECTORIZER" \
    --env-file .env \
    --entrypoint sh \
    "$TRAINER_IMAGE" -c "$1"
}

echo "===== $(date '+%Y-%m-%d %H:%M:%S') : prod retrain cycle start ====="

run_trainer_shell "python3 orchestrator.py && python3 promote.py data_export_results/latest"
status=$?

if [[ $status -eq 0 ]]; then
  if [[ -d data_export_results/latest ]]; then
    rm -rf data_base_results
    cp -r data_export_results/latest data_base_results
    echo "Baseline (data_base_results/) mise à jour pour la comparaison du prochain cycle."
  fi
  date +%s > "$LAST_RUN_FILE"
  echo "===== $(date '+%Y-%m-%d %H:%M:%S') : cycle done (success) ====="
else
  echo "===== $(date '+%Y-%m-%d %H:%M:%S') : cycle done (FAILED, status=$status) - baseline/last_run NOT updated, will retry next tick ====="
fi

exit $status
