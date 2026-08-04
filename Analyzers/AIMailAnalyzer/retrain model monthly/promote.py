"""
promote.py — Déploie les poids d'un run d'entraînement vers le dossier
modèles utilisé en production par ai_mail_classifier.py.

Étape volontairement séparée et manuelle : copier des poids dans
AIMailAnalyzer/models/ change ce que l'analyzer Cortex répond pour de vrais
mails en production. Ce script ne s'exécute jamais tout seul (orchestrator.py
ne l'appelle pas) - un humain lance `python promote.py <results_dir>` après
avoir lu le rapport de compare_results.py.

Sécurités :
  - Sauvegarde horodatée des poids actuellement déployés avant écrasement.
  - Si data_base_results/<model>/metrics.json existe, refuse de promouvoir un
    modèle dont le F1 régresse, sauf --force.
  - --dry-run pour prévisualiser sans rien copier.

Usage :
  python promote.py data_export_results/latest
  python promote.py data_export_results/latest --force
  python promote.py data_export_results/latest --dry-run
"""

import argparse
import json
import os
import shutil
import sys
from datetime import datetime

from dotenv import load_dotenv

load_dotenv()

MODEL_TYPES = ["dangerous", "safe", "unwanted", "spam_dangerous", "safe_suspicious"]
MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models"))
BASE_RESULTS_DIR = "data_base_results"

SUSPICIOUS_API_URL = os.environ.get("SUSPICIOUS_API_URL", "")
SUSPICIOUS_API_TOKEN = os.environ.get("SUSPICIOUS_API_TOKEN", "")


def load_f1(metrics_path):
    """Prefer the golden-set F1 (fixed benchmark, see golden_set.py) when
    present - it's the only apples-to-apples comparison across cycles, since
    the regular f1_score is measured on a different random test slice every
    time the cumulative dataset grows. Falls back to f1_score for old runs
    predating the golden set, or a label with no golden coverage yet."""
    if not os.path.exists(metrics_path):
        return None
    with open(metrics_path) as f:
        data = json.load(f)
    golden = data.get("f1_score_golden")
    return golden if golden is not None else data.get("f1_score")


def push_to_dashboard(manifest, promoted_labels):
    """Best-effort: push this run's per-model metrics to the "AI Model
    Health" dashboard panel (Suspicious/dashboard.AIModelRetrainRun). Never
    raises - a promotion that already succeeded locally must not be
    reported as failed just because the dashboard push didn't land.
    """
    if not SUSPICIOUS_API_URL or not SUSPICIOUS_API_TOKEN:
        print("\nℹ️  SUSPICIOUS_API_URL/SUSPICIOUS_API_TOKEN non configurés (.env) - push dashboard sauté.")
        return

    import requests

    url = SUSPICIOUS_API_URL.rstrip("/") + "/api/stats/ai-model-runs/"
    headers = {"Authorization": f"Token {SUSPICIOUS_API_TOKEN}"}
    pushed, failed = 0, 0

    for label in MODEL_TYPES:
        entry = manifest["models"].get(label)
        if entry is None:
            continue
        payload = {
            "run_timestamp": manifest["run_timestamp"],
            "dataset_dir": manifest["dataset_dir"],
            "label": label,
            "model_name": entry["model_name"],
            "f1_score": entry["f1_score"],
            "accuracy": entry["accuracy"],
            "promoted": label in promoted_labels,
        }
        # Golden-set scores (fixed held-out benchmark, see golden_set.py) -
        # only present once a golden set exists and has coverage for this
        # label's taxonomy; omit rather than send null so older backend
        # versions without these fields don't choke on an unknown key.
        if entry.get("f1_score_golden") is not None:
            payload["f1_score_golden"] = entry["f1_score_golden"]
            payload["accuracy_golden"] = entry["accuracy_golden"]
        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=10)
            resp.raise_for_status()
            pushed += 1
        except Exception as exc:
            failed += 1
            print(f"  ⚠️  dashboard push échoué pour {label}: {exc}")

    print(f"\n📊 Dashboard: {pushed} modèle(s) poussés vers {url}" + (f" ({failed} échec(s))" if failed else ""))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("results_dir", help="Dossier de résultats versionné (ex: data_export_results/latest ou .../2026-07-20_140000)")
    parser.add_argument("--force", action="store_true", help="Promouvoir même en cas de régression du F1")
    parser.add_argument("--dry-run", action="store_true", help="N'écrit rien, affiche seulement ce qui serait fait")
    args = parser.parse_args()

    manifest_path = os.path.join(args.results_dir, "manifest.json")
    if not os.path.exists(manifest_path):
        print(f"❌ {manifest_path} introuvable - {args.results_dir} n'est pas un dossier de résultats valide (attendu: sortie de main_retrainmodels.py).")
        sys.exit(1)

    with open(manifest_path) as f:
        manifest = json.load(f)

    print(f"📦 Run à promouvoir : {args.results_dir} (dataset={manifest['dataset_dir']}, {manifest['run_timestamp']})")

    blocked = []
    to_promote = []

    for label in MODEL_TYPES:
        entry = manifest["models"].get(label)
        if entry is None:
            print(f"  ⚠️  {label}: absent du manifest, ignoré")
            continue

        model_name = entry["model_name"]
        # Same golden-first preference as load_f1() below, so both sides of
        # the comparison are on the fixed benchmark whenever it's available.
        golden_f1 = entry.get("f1_score_golden")
        new_f1 = golden_f1 if golden_f1 is not None else entry["f1_score"]
        src_path = os.path.join(args.results_dir, label, f"{model_name}.pth")

        if not os.path.exists(src_path):
            print(f"  ❌ {label}: {src_path} introuvable, ignoré")
            continue

        base_metrics_path = os.path.join(BASE_RESULTS_DIR, label, "metrics.json")
        base_f1 = load_f1(base_metrics_path)

        if base_f1 is None:
            print(f"  ℹ️  {label}: pas de baseline ({base_metrics_path} absent) - F1 nouveau = {new_f1:.4f}, promotion sans comparaison")
            to_promote.append((label, model_name, src_path))
        elif new_f1 >= base_f1:
            print(f"  ✅ {label}: F1 {base_f1:.4f} → {new_f1:.4f}, promotion")
            to_promote.append((label, model_name, src_path))
        else:
            print(f"  📉 {label}: F1 régresse {base_f1:.4f} → {new_f1:.4f}")
            if args.force:
                print("     --force actif, promotion quand même")
                to_promote.append((label, model_name, src_path))
            else:
                blocked.append(label)

    if blocked:
        print(f"\n❌ {len(blocked)} modèle(s) régressent et --force n'est pas passé: {', '.join(blocked)}")
        print("   Rien n'a été promu. Relancez avec --force pour forcer, ou n'entraînez que sur plus de données.")
        push_to_dashboard(manifest, promoted_labels=set())
        sys.exit(1)

    if not to_promote:
        print("\nRien à promouvoir.")
        return

    if args.dry_run:
        print(f"\n(dry-run) {len(to_promote)} modèle(s) seraient copiés vers {MODELS_DIR}/")
        return

    backup_dir = os.path.join(MODELS_DIR, "..", "models_backup", datetime.now().strftime("%Y-%m-%d_%H%M%S"))
    backup_dir = os.path.abspath(backup_dir)
    os.makedirs(backup_dir, exist_ok=True)

    for label, model_name, src_path in to_promote:
        dst_path = os.path.join(MODELS_DIR, f"{model_name}.pth")
        if os.path.exists(dst_path):
            shutil.copy2(dst_path, os.path.join(backup_dir, f"{model_name}.pth"))
        os.makedirs(MODELS_DIR, exist_ok=True)
        shutil.copy2(src_path, dst_path)
        print(f"  🚀 {model_name}.pth déployé dans {MODELS_DIR}/")

    print(f"\n✅ {len(to_promote)} modèle(s) promus. Sauvegarde des anciens poids : {backup_dir}/")
    print(f"   Pensez à copier {args.results_dir}/ vers {BASE_RESULTS_DIR}/ pour que ce run serve de baseline au prochain.")
    print("   Redémarrez/rebuildez le conteneur AIMailAnalyzer pour qu'il charge les nouveaux poids.")

    push_to_dashboard(manifest, promoted_labels={label for label, _, _ in to_promote})


if __name__ == "__main__":
    main()
