"""
orchestrator.py — Pipeline complet de réentraînement mensuel
=============================================================
Étapes :
  1. generator_dataset.py   → Fetch IMAP incrémental + dataset.pkl cumulatif
  2. main_retrainmodels.py  → Réentraîne les 5 modèles sur ce dataset (sortie versionnée)
  3. compare_results.py     → Évalue et compare les nouveaux modèles à la baseline

Utilisation :
  python orchestrator.py
"""

import os
import sys
import subprocess
from datetime import datetime

# ============================================================
# CONFIGURATION
# ============================================================

# Doit correspondre à DATASET_DIR dans generator_dataset.py
DATASET_DIR = os.environ.get("DATASET_DIR", "data_export")

# Dossier de référence des anciens résultats (pour compare_results.py)
BASE_RESULTS_DIR = "data_base_results"

SCRIPT_GENERATE = "generator_dataset.py"
SCRIPT_RETRAIN = "main_retrainmodels.py"
SCRIPT_COMPARE = "compare_results.py"

PYTHON = sys.executable


def banner(title: str) -> None:
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def run(cmd: list[str], step_name: str) -> None:
    """Lance une commande subprocess et arrête le pipeline en cas d'erreur."""
    print(f"\n▶  Commande : {' '.join(cmd)}\n")
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print(f"\n❌ ERREUR à l'étape « {step_name} » (code {result.returncode})")
        print("   Pipeline interrompu.")
        sys.exit(result.returncode)
    print(f"\n✅ Étape « {step_name} » terminée avec succès.")


def get_results_dir() -> str:
    """
    Reproduit la logique de main_retrainmodels.py pour déduire le dossier de
    résultats de ce run : <dataset_name>_results/latest (pointeur symlink
    mis à jour à chaque run vers le dossier horodaté correspondant).
    """
    dataset_name = os.path.basename(os.path.normpath(DATASET_DIR))
    return os.path.join(f"{dataset_name}_results", "latest")


def main():
    start_time = datetime.now()

    banner("ORCHESTRATEUR — PIPELINE DE RÉENTRAÎNEMENT MENSUEL")
    print(f"  Démarrage : {start_time.strftime('%Y-%m-%d %H:%M:%S')}")

    results_dir = get_results_dir()

    print(f"\n  📁 Dataset cible     : {DATASET_DIR}")
    print(f"  📂 Résultats retrain : {results_dir}")
    print(f"  📊 Résultats base    : {BASE_RESULTS_DIR}")

    # ── Étape 1 : Fetch IMAP incrémental + génération dataset ───
    banner("ÉTAPE 1 — Fetch IMAP & mise à jour du dataset")
    run([PYTHON, SCRIPT_GENERATE], "generator_dataset")

    if not os.path.exists(os.path.join(DATASET_DIR, "dataset.pkl")):
        print(f"\n❌ dataset.pkl introuvable dans {DATASET_DIR} après le fetch.")
        sys.exit(1)

    # ── Étape 2 : Réentraînement des modèles ─────────────────
    banner("ÉTAPE 2 — Réentraînement des modèles")
    run([PYTHON, SCRIPT_RETRAIN, DATASET_DIR], "main_retrainmodels")

    # ── Étape 3 : Comparaison des modèles ────────────────────
    banner("ÉTAPE 3 — Évaluation & Comparaison des modèles")
    if os.path.exists(BASE_RESULTS_DIR):
        run([PYTHON, SCRIPT_COMPARE, BASE_RESULTS_DIR, results_dir], "compare_results")
    else:
        print(f"  ⚠️  {BASE_RESULTS_DIR} n'existe pas encore (premier run) — comparaison sautée.")
        print(f"     Copiez {results_dir}/ vers {BASE_RESULTS_DIR}/ pour servir de baseline aux prochains runs.")

    elapsed = datetime.now() - start_time
    banner("PIPELINE TERMINÉ ✅")
    print(f"  Durée totale : {str(elapsed).split('.')[0]}")
    print(f"  Dataset      : {DATASET_DIR}")
    print(f"  Résultats    : {results_dir}/")
    print()


if __name__ == "__main__":
    main()
