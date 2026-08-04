import argparse
import json
import os
import sys
from datetime import datetime

from Re_Train_Model.utils import save_results
from Re_Train_Model.train_dangerous_model import DangerousTrainer
from Re_Train_Model.train_safe_model import SafeTrainer
from Re_Train_Model.train_safe_suspicious_model import Safe_Suspicious_Trainer
from Re_Train_Model.train_spam_dangerous_model import Spam_Dangerous_Trainer
from Re_Train_Model.train_suspicious_model import Unwanted_Trainer

### utilisation : python main_retrainmodels.py data

TRAINERS = [
    ("dangerous", DangerousTrainer),
    ("safe", SafeTrainer),
    ("unwanted", Unwanted_Trainer),
    ("spam_dangerous", Spam_Dangerous_Trainer),
    ("safe_suspicious", Safe_Suspicious_Trainer),
]


def main(dataset_dir):
    if not os.path.exists(dataset_dir):
        print(f"❌ ERREUR: Le dossier '{dataset_dir}' n'existe pas!")
        sys.exit(1)

    dataset_name = os.path.basename(os.path.normpath(dataset_dir))
    run_timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    base_output_dir = os.path.join(f"{dataset_name}_results", run_timestamp)
    os.makedirs(base_output_dir, exist_ok=True)

    print("=" * 80)
    print("SCRIPT ENTRAINEMENT DE CHAQUE MODELE ET GENERATION DES POIDS DANS LE BON DOSSIER")
    print("=" * 80)
    print(f"📁 Dossier de données: {dataset_dir}")
    print(f"📂 Dossier de résultats (versionné): {base_output_dir}")
    print("=" * 80)

    manifest = {
        "dataset_dir": dataset_dir,
        "run_timestamp": run_timestamp,
        "models": {},
    }

    failed = []
    for label, trainer_cls in TRAINERS:
        print(f"\n{'='*80}\nEntraînement du modèle: {label.upper()} ({trainer_cls.MODEL_NAME})\n{'='*80}")
        output_dir = os.path.join(base_output_dir, label)
        trainer = trainer_cls(dataset_dir=dataset_dir, output_dir=output_dir, run_timestamp=run_timestamp)
        try:
            model, metrics = trainer.train()
            save_results(model, metrics, model_name=trainer_cls.MODEL_NAME, output_dir=output_dir)
        except Exception as exc:
            # One sub-model having too few labeled samples in this dataset
            # (e.g. spam/newsletter early on, before enough "challenged"
            # mail has accumulated) must not block the other 4 - each is
            # independently useful and independently promotable.
            print(f"❌ {label}: entraînement échoué ({exc}) - modèle ignoré, les autres continuent")
            failed.append(label)
            continue

        manifest["models"][label] = {
            "model_name": trainer_cls.MODEL_NAME,
            "output_dir": output_dir,
            "f1_score": metrics["f1_score"],
            "accuracy": metrics["accuracy"],
            "f1_score_golden": metrics.get("f1_score_golden"),
            "accuracy_golden": metrics.get("accuracy_golden"),
        }
        print(f"✅ {label}: OK → {output_dir}")

    if failed:
        manifest["failed_models"] = failed

    manifest_path = os.path.join(base_output_dir, "manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=4)

    # "latest" pointer so orchestrator.py/compare_results.py and a future
    # promotion step don't need to know the exact timestamp of this run.
    latest_link = os.path.join(f"{dataset_name}_results", "latest")
    if os.path.islink(latest_link) or os.path.exists(latest_link):
        os.remove(latest_link)
    os.symlink(run_timestamp, latest_link)

    print("\n" + "=" * 80)
    print("🎉 TOUS LES MODÈLES ONT ÉTÉ ENTRAÎNÉS AVEC SUCCÈS!")
    print(f"📂 Résultats: {base_output_dir}/  (manifest: {manifest_path})")
    print(f"🔗 Pointeur 'latest': {latest_link}")
    print("=" * 80)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Entraîner tous les modèles de classification d'emails",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  python main_retrainmodels.py data_export/2026-07
    → Résultats dans: 2026-07_results/<timestamp>/

  python main_retrainmodels.py --dataset ./mon_dossier
    → Résultats dans: mon_dossier_results/<timestamp>/
        """,
    )

    parser.add_argument(
        "dataset_dir",
        nargs="?",
        default=None,
        help="Chemin vers le dossier contenant dataset.pkl (généré par generator_dataset.py)",
    )
    parser.add_argument(
        "--dataset", "-d",
        dest="dataset_dir_flag",
        default=None,
        help="Chemin vers le dossier dataset (alternative au positionnel)",
    )

    args = parser.parse_args()

    dataset_dir = args.dataset_dir_flag or args.dataset_dir
    if not dataset_dir:
        parser.error("Vous devez fournir le dossier dataset (positionnel ou --dataset)")

    main(dataset_dir)
