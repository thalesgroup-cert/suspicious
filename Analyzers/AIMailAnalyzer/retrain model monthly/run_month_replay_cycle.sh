#!/bin/bash
# run_month_replay_cycle.sh — Pré-prod: simule l'amélioration continue du
# modèle en rejouant l'historique réel de la boîte mail IMAP mois par mois,
# un mois par déclenchement de cron (toutes les 30 min, voir crontab -l).
#
# Différence avec run_monthly_cycle.sh (démo dev avec mails SYNTHÉTIQUES via
# simulate_mail_arrival.py) : ce script utilise generator_dataset_month_replay.py,
# qui fetch un vrai mois calendaire (SINCE/BEFORE) depuis les dossiers IMAP
# réels, en partant de MONTH_REPLAY_START (.env, défaut 2025-08) et en
# avançant d'un mois par exécution - jamais de mail inventé.
#
# Condition d'arrêt : une fois le mois courant atteint et traité,
# generator_dataset_month_replay.py sort avec le code 3 ("rien de nouveau") -
# ce script s'arrête alors AVANT l'entraînement, sans relancer de fetch ni
# de retrain. Cron continue de se déclencher toutes les 30 min sans effet
# (pas de bouclage, pas de retour en mode temps réel - conforme au besoin).
#
# Promotion : comme run_prod_retrain_cycle.sh, promote.py tourne SANS
# --force - une régression de F1 sur un mois donné bloque juste ce
# modèle-là (les métriques sont quand même poussées au dashboard, voir
# promote.py:push_to_dashboard, donc toujours visibles dans l'UI même
# quand un mois ne promeut rien).
#
# Pas de mode "--once"/"forever" comme les deux autres scripts : celui-ci
# fait toujours exactement un cycle par appel (cron fournit la cadence), il
# n'y a pas de boucle interne à désactiver.
#
# Usage (crontab -e) :
#   */30 * * * * cd "/path/to/Analyzers/AIMailAnalyzer/retrain model monthly" && ./run_month_replay_cycle.sh >> run_month_replay_cycle.log 2>&1

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

UP_TO_DATE_EXIT_CODE=3

# Lockfile séparé des deux autres scripts (run_monthly_cycle.sh,
# run_prod_retrain_cycle.sh) - les trois ne doivent jamais se bloquer
# mutuellement s'ils finissent un jour sur le même hôte.
LOCKFILE="/tmp/aimailanalyzer_month_replay_cycle.lock"
exec 200>"$LOCKFILE"
if ! flock -n 200; then
  echo "$(date '+%Y-%m-%d %H:%M:%S') : un cycle de rejeu est déjà en cours (lock: $LOCKFILE) - ignoré." >&2
  exit 0
fi

HF_CACHE="${HF_CACHE:-/home/cert/hf_cache}"
TRAINER_IMAGE="retrain-trainer:latest"
VECTORIZER="${VECTORIZER_PATH:-sentence-transformers/paraphrase-multilingual-mpnet-base-v2}"

# Même raison que dans run_monthly_cycle.sh/run_prod_retrain_cycle.sh : monter
# le parent AIMailAnalyzer/ entier, pas juste ce sous-dossier (utils.py importe
# le vrai ResNetMLP.py/mail_analysis.py via un hack sys.path "../..").
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

echo "===== $(date '+%Y-%m-%d %H:%M:%S') : month-replay cycle start ====="

# Étape 1 seule (fetch du mois) d'abord, pour lire son code de sortie avant
# de décider si l'entraînement doit avoir lieu.
run_trainer_shell "python3 generator_dataset_month_replay.py"
fetch_status=$?

if [[ $fetch_status -eq $UP_TO_DATE_EXIT_CODE ]]; then
  echo "===== $(date '+%Y-%m-%d %H:%M:%S') : mois courant déjà traité - simulation terminée, pas d'entraînement ====="
  exit 0
elif [[ $fetch_status -ne 0 ]]; then
  echo "===== $(date '+%Y-%m-%d %H:%M:%S') : échec du fetch du mois (status=$fetch_status) - entraînement sauté, nouvelle tentative au prochain cron ====="
  exit $fetch_status
fi

echo "--- fetch du mois OK, entraînement + promotion (sans --force) ---"
run_trainer_shell "python3 main_retrainmodels.py data_export && python3 promote.py data_export_results/latest"
train_status=$?

if [[ $train_status -eq 0 && -d data_export_results/latest ]]; then
  rm -rf data_base_results
  cp -r data_export_results/latest data_base_results
  echo "Baseline (data_base_results/) mise à jour pour la comparaison du mois suivant."
fi

echo "===== $(date '+%Y-%m-%d %H:%M:%S') : month-replay cycle done (status=$train_status) ====="
exit $train_status
