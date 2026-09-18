#!/usr/bin/env python3
"""Benchmark de latence pure pour un serveur d'inférence AIMailAnalyzer-like
(AiMailPublicAnalyzer/inference_server/ ou AIMailAnalyzer/inference_server/).

Mesure uniquement le temps de calcul du modèle (appel HTTP direct à
/classify), pas le pipeline Cortex complet - isole le coût de calcul du
bruit du job Cortex (untar, réseau inter-conteneurs, écriture DB).

Réutilisable tel quel pour comparer les deux serveurs plus tard :
    python3 benchmark_inference.py --url http://localhost:8091   # public, 2 modèles
    python3 benchmark_inference.py --url http://localhost:8090   # personal, 5 modèles
"""
from __future__ import annotations

import argparse
import csv
import statistics
import sys
import time
from datetime import datetime

import requests

# Le contenu réel importe peu pour un test de latence pure - seule la
# longueur influence le temps d'embedding. Trois tailles réalistes.
SAMPLE_MAILS = {
    "court (~50 mots)": (
        "Bonjour, merci de bien vouloir valider la facture jointe avant "
        "vendredi. Cordialement, le service comptabilité. Cette demande "
        "concerne le trimestre en cours et nécessite une validation rapide "
        "de votre part pour éviter tout retard de paiement."
    ),
    "moyen (~300 mots)": (
        "Bonjour, dans le cadre du renouvellement annuel de nos contrats "
        "fournisseurs, nous vous prions de bien vouloir prendre connaissance "
        "du document ci-joint détaillant les nouvelles conditions "
        "tarifaires applicables à compter du mois prochain. "
    ) * 15,
    "long (~800 mots)": (
        "Bonjour, suite à notre échange téléphonique de la semaine "
        "dernière concernant la migration de nos infrastructures vers le "
        "nouveau prestataire cloud, je vous transmets ci-joint le compte "
        "rendu détaillé ainsi que le planning prévisionnel des différentes "
        "phases du projet, incluant les tests de charge, la bascule "
        "progressive des services critiques et la période de double "
        "fonctionnement prévue pour sécuriser la transition. "
    ) * 30,
}

WARMUP_CALLS = 1
TIMED_CALLS = 20


def check_health(base_url: str) -> None:
    try:
        resp = requests.get(f"{base_url}/health", timeout=5)
        resp.raise_for_status()
        print(f"Serveur OK : {resp.json()}\n")
    except Exception as exc:
        print(f"ERREUR : le serveur d'inférence ({base_url}) ne répond pas ({exc}).")
        print("Vérifie qu'il est bien buildé et lancé avant de relancer ce script.")
        sys.exit(1)


def time_call(base_url: str, mail_body: str) -> float:
    start = time.perf_counter()
    resp = requests.post(f"{base_url}/classify", json={"mail_body": mail_body}, timeout=60)
    resp.raise_for_status()
    return time.perf_counter() - start


def run_benchmark(base_url: str) -> list[dict]:
    rows = []
    for label, mail_body in SAMPLE_MAILS.items():
        print(f"--- {label} ---")

        for _ in range(WARMUP_CALLS):
            time_call(base_url, mail_body)

        durations = [time_call(base_url, mail_body) for _ in range(TIMED_CALLS)]

        row = {
            "mail_length": label,
            "n_calls": TIMED_CALLS,
            "mean_s": round(statistics.mean(durations), 4),
            "median_s": round(statistics.median(durations), 4),
            "min_s": round(min(durations), 4),
            "max_s": round(max(durations), 4),
        }
        rows.append(row)
        print(
            f"  moyenne={row['mean_s']}s  médiane={row['median_s']}s  "
            f"min={row['min_s']}s  max={row['max_s']}s\n"
        )

    return rows


def save_csv(rows: list[dict], base_url: str) -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"benchmark_results_{timestamp}.csv"
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["server_url", *rows[0].keys()])
        writer.writeheader()
        for row in rows:
            writer.writerow({"server_url": base_url, **row})
    return filename


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--url", default="http://localhost:8091",
        help="URL du serveur d'inférence à tester (défaut: http://localhost:8091, AiMailPublicAnalyzer)",
    )
    args = parser.parse_args()

    print(f"Benchmark de latence — {args.url}")
    print(f"({WARMUP_CALLS} appel(s) de chauffe ignoré(s), {TIMED_CALLS} appels chronométrés par longueur)\n")

    check_health(args.url)
    rows = run_benchmark(args.url)
    csv_path = save_csv(rows, args.url)

    print(f"Résultats sauvegardés dans {csv_path}")


if __name__ == "__main__":
    main()
