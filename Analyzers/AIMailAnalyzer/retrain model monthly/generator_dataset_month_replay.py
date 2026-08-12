"""
generator_dataset_month_replay.py — Rejoue l'historique de la boîte mail
IMAP mois par mois, un mois par exécution, pour simuler l'amélioration
continue du modèle en pré-production sur des mails déjà connus.

Contrairement à generator_dataset.py (fetch "depuis le dernier run", pensé
pour la vraie ingestion continue en prod), ce script fetch une FENÊTRE DE
MOIS FIXE à chaque appel :
  - point de départ : MONTH_REPLAY_START (.env, défaut 2025-08)
  - avance d'un mois à chaque exécution (indépendamment du nombre de mails
    trouvés ce mois-là - même un mois vide fait avancer le curseur, sinon
    la simulation resterait bloquée dessus pour toujours)
  - s'arrête (sans rien fetcher ni avancer) une fois le mois courant traité,
    voir le code de sortie ci-dessous.

Mêmes dossiers IMAP (Re_Train_Model/variable.py:folders), même schéma de
dataset cumulatif (hash, folder, body, mpnet_vect) et mêmes helpers
d'extraction du corps du mail forwardé que generator_dataset.py, réutilisés
tels quels - main_retrainmodels.py n'a rien à changer, il continue de lire
data_export/dataset.pkl normalement.

État de progression persisté séparément dans .month_replay_state.json (PAS
.fetch_state.json - les deux mécanismes de curseur ne doivent jamais se
marcher dessus, generator_dataset.py reste inchangé et utilisable seul par
ailleurs).

Code de sortie :
  0  un mois a été traité (mails fetchés ou non) - le run appelant doit
     enchaîner sur l'entraînement.
  3  le mois courant est déjà atteint et traité - rien de nouveau à faire,
     le run appelant doit sauter l'entraînement (pas de nouvelle donnée).

Usage:
  python generator_dataset_month_replay.py
"""
import email
import json
import os
import sys
from datetime import datetime

import pandas as pd
from dateutil.relativedelta import relativedelta
from sentence_transformers import SentenceTransformer

from generator_dataset import (
    DATASET_DIR,
    DATASET_PATH,
    VECTORIZER_PATH,
    _decode_subject,
    _extract_forwarded_body,
    connect_imap,
)
from Re_Train_Model.utils import calculate_hash, vectorize_mails
from Re_Train_Model.variable import folders

MONTH_REPLAY_START = os.environ.get("MONTH_REPLAY_START", "2025-08")
STATE_PATH = os.path.join(DATASET_DIR, ".month_replay_state.json")

UP_TO_DATE_EXIT_CODE = 3


def _load_last_processed_month():
    if not os.path.exists(STATE_PATH):
        return None
    with open(STATE_PATH) as f:
        return datetime.strptime(json.load(f)["last_processed_month"], "%Y-%m")


def _save_last_processed_month(month):
    os.makedirs(DATASET_DIR, exist_ok=True)
    with open(STATE_PATH, "w") as f:
        json.dump({"last_processed_month": month.strftime("%Y-%m")}, f, indent=2)


def _next_month_to_process():
    last = _load_last_processed_month()
    if last is None:
        return datetime.strptime(MONTH_REPLAY_START, "%Y-%m")
    return last + relativedelta(months=1)


def fetch_folder_messages_for_month(conn, folder, month_start):
    """Comme generator_dataset.fetch_folder_messages, mais borné à
    [month_start, month_start + 1 mois) au lieu d'un SINCE ouvert - mêmes
    règles d'extraction (mail forwardé message/rfc822 uniquement)."""
    status, _ = conn.select(f'"{folder}"', readonly=True)
    if status != "OK":
        print(f"  ⚠️  Impossible d'ouvrir le dossier IMAP {folder!r} (existe-t-il ? nom exact ?), ignoré.")
        return []

    month_end = month_start + relativedelta(months=1)
    since_str = month_start.strftime("%d-%b-%Y")
    before_str = month_end.strftime("%d-%b-%Y")
    status, data = conn.search(None, f'(SINCE "{since_str}" BEFORE "{before_str}")')
    if status != "OK" or not data or not data[0]:
        return []

    results = []
    for num in data[0].split():
        status, msg_data = conn.fetch(num, "(RFC822)")
        if status != "OK":
            continue
        msg = email.message_from_bytes(msg_data[0][1])
        subject = _decode_subject(msg)

        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "message/rfc822":
                    body = _extract_forwarded_body(part)
                    break

        if not body:
            print(f"    ⚠️  {subject[:60]!r}: pas de pièce jointe message/rfc822, ignoré")
            continue

        results.append((calculate_hash(body.encode("utf-8")), body))

    return results


def replay_month(month_start):
    os.makedirs(DATASET_DIR, exist_ok=True)
    if os.path.exists(DATASET_PATH):
        df = pd.read_pickle(DATASET_PATH)
    else:
        df = pd.DataFrame(columns=["hash", "folder", "body", "mpnet_vect"])

    month_end = month_start + relativedelta(months=1)
    print(f"=== Rejeu du mois {month_start:%Y-%m} ({month_start:%d-%b-%Y} → {month_end:%d-%b-%Y}) ===")
    conn = connect_imap()

    new_count = 0
    try:
        for folder in folders:
            print(f"\n{'='*60}\nDossier: {folder}\n{'='*60}")
            messages = fetch_folder_messages_for_month(conn, folder, month_start)
            folder_new = 0
            for mail_hash, body in messages:
                if df["hash"].eq(mail_hash).any():
                    continue
                new_row = {"hash": mail_hash, "folder": folder, "body": body, "mpnet_vect": None}
                df = pd.concat([df, pd.DataFrame([new_row])], ignore_index=True)
                new_count += 1
                folder_new += 1
            print(f"  {len(messages)} mail(s) trouvé(s), {folder_new} nouveau(x)")
    finally:
        conn.logout()

    print(f"\n{new_count} nouveaux mails ajoutés pour {month_start:%Y-%m} ({len(df)} au total dans le dataset cumulatif).")

    if new_count > 0:
        print("Chargement du vectorizer...")
        vectorizer = SentenceTransformer(VECTORIZER_PATH)
        print("Vectorisation des nouveaux mails...")
        vectorize_mails(df, vectorizer)

    df.to_pickle(DATASET_PATH)
    # Le curseur avance même si new_count == 0 (mois sans mail challengé) -
    # sinon la simulation resterait bloquée sur ce mois indéfiniment et
    # n'atteindrait jamais le mois courant.
    _save_last_processed_month(month_start)
    print(f"✅ {DATASET_PATH} sauvegardé - mois {month_start:%Y-%m} marqué comme traité.")


def main():
    next_month = _next_month_to_process()
    current_month = datetime.now().replace(day=1)

    if next_month > current_month:
        print(f"✅ Mois courant ({current_month:%Y-%m}) déjà traité - rien à faire, simulation terminée.")
        sys.exit(UP_TO_DATE_EXIT_CODE)

    replay_month(next_month)


if __name__ == "__main__":
    main()
