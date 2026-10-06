"""
generator_dataset.py — Récupère les mails "challenged" que les analystes ont
classés dans la boîte mail de revue (une IMAP folder par catégorie de la
taxonomie, cf. Re_Train_Model/variable.py:folders) et les ajoute au dataset
d'entraînement cumulatif consommé par main_retrainmodels.py.

Le fetch IMAP est incrémental (SINCE une date persistée entre deux runs) car
le volume est faible (~10 mails/mois toutes catégories confondues) - le
dataset doit s'accumuler dans la durée, pas repartir de zéro chaque mois.

Usage:
  python generator_dataset.py                  # depuis le dernier run (ou début du mois en cours au 1er run)
  python generator_dataset.py --since 2026-01-01
"""

import argparse
import email
import imaplib
import json
import os
from datetime import datetime
from email.header import decode_header

import html2text
import pandas as pd
from dotenv import load_dotenv
from sentence_transformers import SentenceTransformer

from Re_Train_Model.utils import calculate_hash, vectorize_mails
from Re_Train_Model.variable import folders

load_dotenv()

IMAP_HOST = os.environ["IMAP_HOST"]
IMAP_PORT = int(os.environ.get("IMAP_PORT", 993))
IMAP_USER = os.environ["IMAP_USER"]
IMAP_PASSWORD = os.environ["IMAP_PASSWORD"]
IMAP_USE_SSL = os.environ.get("IMAP_USE_SSL", "true").lower() == "true"

# Vectoriseur pinné livré avec l'analyzer (Analyzers/AIMailAnalyzer/vectorizers/...)
# — même modèle que celui utilisé en inférence, sinon les embeddings ne seraient
# pas comparables entre entraînement et production.
VECTORIZER_PATH = os.environ.get(
    "VECTORIZER_PATH",
    os.path.abspath(os.path.join(
        os.path.dirname(__file__), "..", "vectorizers", "paraphrase-multilingual-mpnet-base-v2",
    )),
)

DATASET_DIR = os.environ.get("DATASET_DIR", "data_export")
STATE_PATH = os.path.join(DATASET_DIR, ".fetch_state.json")
DATASET_PATH = os.path.join(DATASET_DIR, "dataset.pkl")


def _load_last_fetch_date():
    if os.path.exists(STATE_PATH):
        with open(STATE_PATH) as f:
            return datetime.strptime(json.load(f)["last_fetch_date"], "%Y-%m-%d")
    # First ever run: default to the start of the current month, matching the
    # monthly cadence analysts file "challenged" mails at.
    return datetime.now().replace(day=1)


def _save_last_fetch_date(date):
    os.makedirs(DATASET_DIR, exist_ok=True)
    with open(STATE_PATH, "w") as f:
        json.dump({"last_fetch_date": date.strftime("%Y-%m-%d")}, f, indent=2)


def connect_imap():
    if IMAP_USE_SSL:
        conn = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
    else:
        conn = imaplib.IMAP4(IMAP_HOST, IMAP_PORT)
    conn.login(IMAP_USER, IMAP_PASSWORD)
    return conn


def _decode_subject(msg):
    subject_header = msg.get("Subject", "No Subject")
    subject, encoding = decode_header(subject_header)[0] if subject_header else ("No Subject", None)
    if isinstance(subject, bytes):
        subject = subject.decode(encoding or "utf-8", errors="replace")
    return subject


def _extract_forwarded_body(part):
    """Un mail 'challenged' filé par un analyste est un message forwardé
    (message/rfc822) contenant l'email suspect original en pièce jointe.

    A message/rfc822 part's payload is a single-element list holding the
    attached Message object directly - no manual re-parsing needed.
    """
    attached_msg = part.get_payload(0)

    markdown_body = ""
    for att_part in attached_msg.walk():
        if att_part.get_content_type() in ("text/plain", "text/html"):
            payload = att_part.get_payload(decode=True)
            if not payload:
                continue
            encoding = att_part.get_content_charset() or "utf-8"
            try:
                html_content = payload.decode(encoding)
            except (UnicodeDecodeError, LookupError):
                html_content = payload.decode("utf-8", errors="replace")
            h = html2text.HTML2Text()
            h.ignore_links = False
            h.ignore_images = True
            markdown_body += h.handle(html_content) + "\n"

    return markdown_body


def fetch_folder_messages(conn, folder, since_date):
    """Retourne [(hash, body)] pour les messages de `folder` reçus depuis since_date."""
    status, _ = conn.select(f'"{folder}"', readonly=True)
    if status != "OK":
        print(f"  ⚠️  Impossible d'ouvrir le dossier IMAP {folder!r} (existe-t-il ? nom exact ?), ignoré.")
        return []

    search_date = since_date.strftime("%d-%b-%Y")
    status, data = conn.search(None, f'(SINCE "{search_date}")')
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


def generate_dataset(since_date):
    os.makedirs(DATASET_DIR, exist_ok=True)

    if os.path.exists(DATASET_PATH):
        df = pd.read_pickle(DATASET_PATH)
    else:
        df = pd.DataFrame(columns=["hash", "folder", "body", "mpnet_vect"])

    print(f"Fetch IMAP depuis le {since_date:%Y-%m-%d} sur {IMAP_HOST} ...")
    conn = connect_imap()

    new_count = 0
    try:
        for folder in folders:
            print(f"\n{'='*60}\nDossier: {folder}\n{'='*60}")
            messages = fetch_folder_messages(conn, folder, since_date)
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

    print(f"\n{new_count} nouveaux mails ajoutés ({len(df)} au total dans le dataset cumulatif).")

    if new_count > 0:
        print("Chargement du vectorizer...")
        vectorizer = SentenceTransformer(VECTORIZER_PATH)
        print("Vectorisation des nouveaux mails...")
        vectorize_mails(df, vectorizer)

    df.to_pickle(DATASET_PATH)
    _save_last_fetch_date(datetime.now())
    print(f"✅ {DATASET_PATH} sauvegardé ({len(df)} mails, {new_count} nouveaux ce run)")

    return DATASET_PATH


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Récupère les mails 'challenged' classés par les analystes dans la boîte mail IMAP.",
    )
    parser.add_argument(
        "--since", default=None,
        help="Date de début du fetch IMAP, format YYYY-MM-DD (défaut: dernier run, ou début du mois en cours au 1er run).",
    )
    args = parser.parse_args()

    since_date = datetime.strptime(args.since, "%Y-%m-%d") if args.since else _load_last_fetch_date()
    generate_dataset(since_date)
