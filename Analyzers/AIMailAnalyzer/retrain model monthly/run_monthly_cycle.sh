#!/bin/bash
# run_monthly_cycle.sh — Dev-only continuous simulator, NOT part of the
# production pipeline. Simulates the full monthly cadence end to end, with
# "monthly" compressed to a configurable interval (default 30 min):
#
#   1. Analysts triage ~10 more "challenged" mails into the taxonomy folders
#      (simulate_mail_arrival.py --once, reused from the mailbox seeding tool)
#   2. Incremental IMAP fetch into the cumulative dataset (generator_dataset.py)
#   3. Retrain all 5 sub-models on the updated dataset (main_retrainmodels.py)
#   4. Promote + push run metrics to the Suspicious "AI Model Health" dashboard
#      panel (promote.py) - auto-promoted here since this is a simulation, not
#      a real production deploy (see promote.py's own docstring for why that
#      step is manual/gated in the real flow).
#
# Steps 2-4 run inside the retrain-trainer:latest throwaway image (see
# Dockerfile.trainer) because `pip install torch` into a host venv hits a
# per-user disk quota in this sandbox that Docker builds don't.
#
# Each sub-model's training run is logged to W&B (see
# Re_Train_Model/utils.py:_wandb_start_run) - epoch loss/accuracy/time, plus
# a current-vs-previous-cycle comparison of how many samples went into each
# taxonomy label (persisted in label_count_history.json, independent of
# W&B's online/offline mode). Defaults to WANDB_MODE=offline (local files
# under ./wandb/, no account needed) - export WANDB_MODE=online +
# WANDB_API_KEY before invoking to push to a real W&B project instead.
#
# Driven by cron for the "every 30 min" cadence (crontab -l), each firing
# running `--once` under a flock so an overrunning cycle can't overlap with
# the next trigger - NOT the old nohup-loop mode, which didn't survive a
# session/terminal boundary. --interval/forever mode is kept for manual demos.
#
# Usage:
#   ./run_monthly_cycle.sh --once            # single cycle then exit (what cron runs)
#   ./run_monthly_cycle.sh                   # forever, one cycle every 30 min (manual demo)
#   ./run_monthly_cycle.sh --interval 300    # every 5 min, for faster demoing

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

INTERVAL=1800
ONCE=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --interval) INTERVAL="$2"; shift 2 ;;
    --once) ONCE=true; shift ;;
    *) echo "Unknown arg: $1" >&2; exit 1 ;;
  esac
done

# Guards against overlap between two triggers of this script - matters once
# it's driven by cron (*/30 * * * * ... --once, see crontab -l) rather than
# only the old nohup infinite-loop mode: if a cycle ever runs past 30min,
# cron would otherwise fire a second overlapping cycle on top of it.
LOCKFILE="/tmp/aimailanalyzer_retrain_cycle.lock"
exec 200>"$LOCKFILE"
if ! flock -n 200; then
  echo "$(date '+%Y-%m-%d %H:%M:%S') : another retrain cycle is already running (lock: $LOCKFILE) - skipping." >&2
  exit 0
fi

HF_CACHE="/home/cert/hf_cache"
SEED_PY="/home/cert/seed_venv/bin/python"
TRAINER_IMAGE="retrain-trainer:latest"
VECTORIZER="sentence-transformers/paraphrase-multilingual-mpnet-base-v2"

# Must mount the whole AIMailAnalyzer/ parent, not just this subfolder:
# Re_Train_Model/utils.py imports the real production ResNetMLP.py /
# mail_analysis.py via a "../.." sys.path hack (see its own comment) so the
# retrain pipeline trains the exact architecture ai_mail_classifier.py loads
# in production, not a drifted local copy. Mounting only this subfolder
# leaves that parent invisible inside the container -> ModuleNotFoundError.
AIMAILANALYZER_DIR="$(cd .. && pwd)"

# W&B run monitoring (per-epoch loss/accuracy/time + current-vs-previous
# label sample counts, see Re_Train_Model/utils.py:_wandb_start_run).
# Offline by default: no W&B account/API key in this sandbox, and the
# pypi.org/proxy flakiness seen elsewhere this session makes depending on
# the wandb.ai cloud service a bad default. Runs land under ./wandb/ and can
# be pushed later with `wandb sync <run dir>` if you set up a real account.
mkdir -p "$AIMAILANALYZER_DIR/retrain model monthly/wandb"
export WANDB_MODE="${WANDB_MODE:-offline}"
export WANDB_PROJECT="${WANDB_PROJECT:-aimailanalyzer-retrain}"

run_trainer() {
  docker run --rm --network host \
    -v "$AIMAILANALYZER_DIR:/aimailanalyzer" \
    -w "/aimailanalyzer/retrain model monthly" \
    -v "$HF_CACHE:/root/.cache/huggingface" \
    -e HF_HOME=/root/.cache/huggingface \
    -e VECTORIZER_PATH="$VECTORIZER" \
    -e WANDB_MODE="$WANDB_MODE" \
    -e WANDB_PROJECT="$WANDB_PROJECT" \
    -e WANDB_DIR="/aimailanalyzer/retrain model monthly/wandb" \
    --env-file .env \
    "$TRAINER_IMAGE" "$@"
}

while true; do
  echo "===== $(date '+%Y-%m-%d %H:%M:%S') : monthly cycle start ====="

  echo "--- [1/4] analysts triage: +10 mails across taxonomy folders ---"
  "$SEED_PY" simulate_mail_arrival.py --once

  echo "--- [2/4] incremental IMAP fetch -> cumulative dataset ---"
  run_trainer generator_dataset.py

  echo "--- [3/4] retrain all sub-models ---"
  run_trainer main_retrainmodels.py data_export

  echo "--- [4/4] promote + push metrics to AI Model Health dashboard ---"
  run_trainer promote.py data_export_results/latest --force

  echo "===== $(date '+%Y-%m-%d %H:%M:%S') : cycle done ====="

  if $ONCE; then
    break
  fi
  echo "Sleeping ${INTERVAL}s until next cycle..."
  sleep "$INTERVAL"
done
