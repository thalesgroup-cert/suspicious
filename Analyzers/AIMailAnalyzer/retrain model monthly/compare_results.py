import os
import json
import argparse
from datetime import datetime
from pathlib import Path
import pandas as pd
from typing import Dict, List, Tuple

# code qui permet de compare les resulata 
def load_metrics(metrics_path: str) -> Dict:
    """
    Charge le fichier metrics.json
    
    Args:
        metrics_path: Chemin vers le fichier metrics.json
        
    Returns:
        Dictionnaire contenant les métriques
    """
    try:
        with open(metrics_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"⚠️  Fichier non trouvé: {metrics_path}")
        return None
    except json.JSONDecodeError:
        print(f"⚠️  Erreur de lecture JSON: {metrics_path}")
        return None


def extract_f1_score(metrics: Dict) -> float:
    """
    Extrait le F1 score du dictionnaire de métriques
    
    Args:
        metrics: Dictionnaire de métriques
        
    Returns:
        F1 score (0.0 si non trouvé)
    """
    if metrics is None:
        return 0.0
    
    # Chercher le F1 score dans différentes structures possibles
    if 'f1_score' in metrics:
        return float(metrics['f1_score'])
    elif 'f1' in metrics:
        return float(metrics['f1'])
    elif 'test_f1' in metrics:
        return float(metrics['test_f1'])
    elif 'validation_f1' in metrics:
        return float(metrics['validation_f1'])
    else:
        print(f"⚠️  F1 score non trouvé dans les métriques")
        return 0.0


def compare_models(base_dir: str, new_dir: str) -> pd.DataFrame:
    """
    Compare les métriques entre deux dossiers de résultats
    
    Args:
        base_dir: Dossier de base (ex: data_base_results)
        new_dir: Nouveau dossier (ex: dataset_new_mails_results)
        
    Returns:
        DataFrame avec la comparaison
    """
    # Liste des sous-dossiers de modèles à comparer
    model_types = [
        "dangerous",
        "safe",
        "unwanted",
        "spam_dangerous",
        "safe_suspicious"
    ]
    
    results = []
    
    print("=" * 80)
    print("COMPARAISON DES MODÈLES")
    print("=" * 80)
    print(f"📁 Dossier de base: {base_dir}")
    print(f"📁 Nouveau dossier: {new_dir}")
    print("=" * 80)
    
    for model_type in model_types:
        print(f"\n🔍 Analyse du modèle: {model_type.upper()}")
        
        # Chemins vers les fichiers metrics.json
        base_metrics_path = os.path.join(base_dir, model_type, "metrics.json")
        new_metrics_path = os.path.join(new_dir, model_type, "metrics.json")
        
        # Charger les métriques
        base_metrics = load_metrics(base_metrics_path)
        new_metrics = load_metrics(new_metrics_path)
        
        # Extraire les F1 scores
        base_f1 = extract_f1_score(base_metrics)
        new_f1 = extract_f1_score(new_metrics)
        
        # Déterminer le meilleur
        if base_f1 > new_f1:
            best = "BASE"
            best_f1 = base_f1
            improvement = 0
        elif new_f1 > base_f1:
            best = "NEW"
            best_f1 = new_f1
            improvement = ((new_f1 - base_f1) / base_f1 * 100) if base_f1 > 0 else 100
        else:
            best = "EQUAL"
            best_f1 = base_f1
            improvement = 0
        
        # Afficher les résultats
        print(f"  Base F1:    {base_f1:.4f}")
        print(f"  New F1:     {new_f1:.4f}")
        print(f"  🏆 Meilleur: {best} (F1: {best_f1:.4f})")
        if improvement > 0:
            print(f"  📈 Amélioration: +{improvement:.2f}%")
        elif improvement < 0:
            print(f"  📉 Dégradation: {improvement:.2f}%")
        
        # Stocker les résultats
        results.append({
            'Model': model_type,
            'Base_F1': base_f1,
            'New_F1': new_f1,
            'Best': best,
            'Best_F1': best_f1,
            'Improvement_%': improvement,
            'Base_Path': base_metrics_path if base_metrics else "N/A",
            'New_Path': new_metrics_path if new_metrics else "N/A"
        })
    
    # Créer le DataFrame
    df = pd.DataFrame(results)
    
    return df


def generate_comparison_report(df: pd.DataFrame, output_dir: str = "."):
    """
    Génère un rapport de comparaison
    
    Args:
        df: DataFrame avec les comparaisons
        output_dir: Dossier où sauvegarder le rapport
    """
    timestamp = datetime.now().strftime("%Y_%m_%d_%H%M%S")
    report_path = os.path.join(output_dir, f"comparison_report_{timestamp}.txt")
    csv_path = os.path.join(output_dir, f"comparison_report_{timestamp}.csv")
    
    # Sauvegarder le CSV
    df.to_csv(csv_path, index=False)
    print(f"\n💾 Rapport CSV sauvegardé: {csv_path}")
    
    # Générer le rapport texte
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write("RAPPORT DE COMPARAISON DES MODÈLES\n")
        f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 80 + "\n\n")
        
        # Résumé global
        total_models = len(df)
        base_wins = len(df[df['Best'] == 'BASE'])
        new_wins = len(df[df['Best'] == 'NEW'])
        equals = len(df[df['Best'] == 'EQUAL'])
        
        f.write("RÉSUMÉ GLOBAL\n")
        f.write("-" * 80 + "\n")
        f.write(f"Total de modèles comparés: {total_models}\n")
        f.write(f"Modèles BASE meilleurs:    {base_wins} ({base_wins/total_models*100:.1f}%)\n")
        f.write(f"Modèles NEW meilleurs:     {new_wins} ({new_wins/total_models*100:.1f}%)\n")
        f.write(f"Modèles égaux:             {equals} ({equals/total_models*100:.1f}%)\n\n")
        
        # Détails par modèle
        f.write("DÉTAILS PAR MODÈLE\n")
        f.write("-" * 80 + "\n")
        for _, row in df.iterrows():
            f.write(f"\n{row['Model'].upper()}\n")
            f.write(f"  Base F1:      {row['Base_F1']:.4f}\n")
            f.write(f"  New F1:       {row['New_F1']:.4f}\n")
            f.write(f"  Meilleur:     {row['Best']} (F1: {row['Best_F1']:.4f})\n")
            if row['Improvement_%'] != 0:
                f.write(f"  Variation:    {row['Improvement_%']:+.2f}%\n")
        
        # Recommandations
        f.write("\n" + "=" * 80 + "\n")
        f.write("RECOMMANDATIONS\n")
        f.write("=" * 80 + "\n")
        
        if new_wins > base_wins:
            f.write("✅ Les nouveaux modèles sont globalement meilleurs.\n")
            f.write("   Recommandation: Remplacer les modèles de base par les nouveaux.\n")
        elif base_wins > new_wins:
            f.write("⚠️  Les modèles de base sont globalement meilleurs.\n")
            f.write("   Recommandation: Conserver les modèles de base.\n")
        else:
            f.write("➡️  Performances équilibrées entre les deux ensembles.\n")
            f.write("   Recommandation: Analyser au cas par cas.\n")
        
        # Modèles à remplacer
        f.write("\nMODÈLES À REMPLACER (NEW > BASE):\n")
        to_replace = df[df['Best'] == 'NEW']
        if len(to_replace) > 0:
            for _, row in to_replace.iterrows():
                f.write(f"  - {row['Model']}: +{row['Improvement_%']:.2f}%\n")
        else:
            f.write("  Aucun\n")
    
    print(f"💾 Rapport TXT sauvegardé: {report_path}")
    
    return report_path, csv_path


def display_summary(df: pd.DataFrame):
    """
    Affiche un résumé visuel dans la console
    
    Args:
        df: DataFrame avec les comparaisons
    """
    print("\n" + "=" * 80)
    print("📊 RÉSUMÉ DE LA COMPARAISON")
    print("=" * 80)
    
    # Tableau formaté
    print("\n{:<20} {:>12} {:>12} {:>10} {:>15}".format(
        "MODÈLE", "BASE F1", "NEW F1", "MEILLEUR", "AMÉLIORATION"
    ))
    print("-" * 80)
    
    for _, row in df.iterrows():
        improvement_str = f"{row['Improvement_%']:+.2f}%" if row['Improvement_%'] != 0 else "="
        emoji = "🟢" if row['Best'] == 'NEW' else "🔵" if row['Best'] == 'BASE' else "⚪"
        
        print("{:<20} {:>12.4f} {:>12.4f} {:>10} {:>15}".format(
            emoji + " " + row['Model'],
            row['Base_F1'],
            row['New_F1'],
            row['Best'],
            improvement_str
        ))
    
    print("-" * 80)
    
    # Statistiques globales
    total = len(df)
    base_wins = len(df[df['Best'] == 'BASE'])
    new_wins = len(df[df['Best'] == 'NEW'])
    
    print(f"\n🏆 Résultat global:")
    print(f"   BASE meilleur: {base_wins}/{total} ({base_wins/total*100:.1f}%)")
    print(f"   NEW meilleur:  {new_wins}/{total} ({new_wins/total*100:.1f}%)")
    print("=" * 80 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Comparer les métriques F1 entre deux dossiers de résultats de modèles",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  python compare_models.py data_base_results dataset_new_mails_results
  python compare_models.py -b data_base_results -n dataset_new_mails_results -o ./reports
        """
    )
    
    parser.add_argument(
        'base_dir',
        nargs='?',
        help='Dossier de résultats de base (ex: data_base_results)'
    )
    
    parser.add_argument(
        'new_dir',
        nargs='?',
        help='Dossier de nouveaux résultats (ex: dataset_new_mails_results)'
    )
    
    parser.add_argument(
        '--base', '-b',
        dest='base_dir_flag',
        help='Dossier de résultats de base (alternative)'
    )
    
    parser.add_argument(
        '--new', '-n',
        dest='new_dir_flag',
        help='Dossier de nouveaux résultats (alternative)'
    )
    
    parser.add_argument(
        '--output', '-o',
        default='.',
        help='Dossier de sortie pour les rapports (défaut: dossier courant)'
    )
    
    args = parser.parse_args()
    
    # Déterminer les dossiers à utiliser
    base_dir = args.base_dir_flag if args.base_dir_flag else args.base_dir
    new_dir = args.new_dir_flag if args.new_dir_flag else args.new_dir
    
    # Vérifier que les arguments sont fournis
    if not base_dir or not new_dir:
        parser.error("Vous devez fournir les deux dossiers à comparer")
    
    # Vérifier que les dossiers existent
    if not os.path.exists(base_dir):
        print(f"❌ ERREUR: Le dossier '{base_dir}' n'existe pas!")
        return
    
    if not os.path.exists(new_dir):
        print(f"❌ ERREUR: Le dossier '{new_dir}' n'existe pas!")
        return
    
    # Créer le dossier de sortie si nécessaire
    os.makedirs(args.output, exist_ok=True)
    
    # Effectuer la comparaison
    df = compare_models(base_dir, new_dir)
    
    # Afficher le résumé
    display_summary(df)
    
    # Générer les rapports
    report_txt, report_csv = generate_comparison_report(df, args.output)
    
    print("\n✅ Comparaison terminée avec succès!")


if __name__ == "__main__":
    main()