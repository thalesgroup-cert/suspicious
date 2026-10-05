#!/bin/bash
# run_month_replay_backfill.sh — Rejoue TOUS les mois en attente d'affilée,
# en un seul lancement manuel, au lieu d'attendre un déclenchement de cron
# par mois (run_month_replay_cycle.sh reste inchangé : "un cycle par appel",
# c'est ce script qui fournit la boucle, pas lui).
#
# Contrairement à un simple `while ./run_month_replay_cycle.sh; do :; done`,
# ce script distingue explicitement les 3 issues possibles d'un cycle
# (voir run_month_replay_cycle.sh) au lieu de s'arrêter sur n'importe quel
# code de sortie non-nul :
#   0  mois traité (promu ou non, ex. régression F1 bloquée - voir
#      promote.py/run_month_replay_cycle.sh) → on enchaîne sur le suivant.
#   3  mois courant déjà atteint → rattrapage terminé, arrêt propre.
#   *  vraie erreur (dataset/manifest introuvable, docker en échec, IMAP
#      injoignable...) → arrêt immédiat, ne PAS continuer en boucle sur
#      une panne comme si de rien n'était.
#
# Chaque mois traité apparaît comme un point séparé dans le dashboard "AI
# Model Health" (promote.py pousse ses métriques à chaque cycle, promu ou
# non) - c'est le but recherché, contrairement à un fetch groupé de tous
# les mois suivi d'un seul entraînement.
#
# Usage :
#   ./run_month_replay_backfill.sh
#
# Le point de départ du rattrapage reste MONTH_REPLAY_START dans .env
# (édite-le avant de lancer si tu veux repartir d'un autre mois que celui
# où le curseur .month_replay_state.json s'est arrêté).

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

UP_TO_DATE_EXIT_CODE=3
MAX_MONTHS=120  # garde-fou (10 ans) contre une vraie boucle infinie en cas de bug

# Verrou séparé de celui de run_month_replay_cycle.sh - empêche deux
# rattrapages de tourner en parallèle (le cycle interne, lui, se
# contenterait de sauter silencieusement si son propre verrou est pris,
# ce qui ferait spinner ce script pour rien).
LOCKFILE="/tmp/aimailanalyzer_month_replay_backfill.lock"
exec 201>"$LOCKFILE"
if ! flock -n 201; then
  echo "$(date '+%Y-%m-%d %H:%M:%S') : un rattrapage est déjà en cours (lock: $LOCKFILE) - abandon." >&2
  exit 1
fi

LOGFILE="run_month_replay_backfill_$(date '+%Y%m%d_%H%M%S').log"
echo "===== $(date '+%Y-%m-%d %H:%M:%S') : début du rattrapage (log: $LOGFILE) ====="

declare -a SUMMARY=()
count=0

while (( count < MAX_MONTHS )); do
  count=$((count + 1))

  # $? (pas PIPESTATUS) : "set -o pipefail" est hérité dans le sous-shell de
  # cette substitution de commande, donc le code de sortie du sous-shell
  # lui-même (récupérable via $? juste après) reflète déjà correctement
  # celui de run_month_replay_cycle.sh - PIPESTATUS, lui, ne s'applique
  # qu'à un pipe exécuté directement dans CE shell, pas dans un sous-shell.
  output=$(./run_month_replay_cycle.sh 2>&1 | tee -a "$LOGFILE")
  status=$?

  # run_month_replay_cycle.sh convertit volontairement le cas "rien à faire"
  # en exit 0 (pas 3) pour son usage cron d'origine - le code 3 ne sort donc
  # jamais de ce script, seul le message texte permet de détecter l'arrêt.
  if grep -q "mois courant déjà traité" <<<"$output"; then
    echo "===== $(date '+%Y-%m-%d %H:%M:%S') : rattrapé jusqu'au mois courant. ====="
    break
  fi

  if [[ $status -ne 0 ]]; then
    echo "===== $(date '+%Y-%m-%d %H:%M:%S') : arrêt sur erreur réelle (status=$status) - voir $LOGFILE ====="
    exit "$status"
  fi

  month=$(grep -oE '=== Rejeu du mois [0-9]{4}-[0-9]{2}' <<<"$output" | grep -oE '[0-9]{4}-[0-9]{2}' | head -n1)
  month="${month:-?}"

  if grep -q "Baseline (data_base_results/) mise à jour" <<<"$output"; then
    outcome="promu"
  elif grep -q "Aucune promotion ce mois-ci" <<<"$output"; then
    outcome="bloqué (régression F1)"
  elif grep -qE '^0 nouveaux mails ajoutés' <<<"$output"; then
    outcome="aucun mail ce mois"
  else
    outcome="traité"
  fi

  SUMMARY+=("$month  $outcome")
  echo "  → mois $month : $outcome"
done

if (( count >= MAX_MONTHS )); then
  echo "===== $(date '+%Y-%m-%d %H:%M:%S') : garde-fou de $MAX_MONTHS cycles atteint - arrêt de précaution. ====="
fi

echo ""
echo "===== Résumé du rattrapage ====="
if [[ ${#SUMMARY[@]} -eq 0 ]]; then
  echo "Rien à traiter - déjà à jour."
else
  printf '%s\n' "${SUMMARY[@]}"
fi
echo "================================"
echo "Log complet : $LOGFILE"
