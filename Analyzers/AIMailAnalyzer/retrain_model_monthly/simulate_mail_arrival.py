"""
simulate_mail_arrival.py — Dev-only continuous simulator. Unlike
seed_greenmail_dataset.py's one-shot bulk seed, this adds a small batch of
new "challenged" mails on a recurring interval, mimicking analysts
gradually triaging mail over time — so generator_dataset.py's incremental
IMAP fetch and main_retrainmodels.py have a genuinely growing dataset to
work against between runs, not a static one seeded once.

Reuses the same content generators, folder taxonomy, and realistic
class-imbalance weights as seed_greenmail_dataset.py (imported directly,
not duplicated) so the ongoing trickle matches the same shape as the
initial bulk seed.

Usage:
  python simulate_mail_arrival.py                       # forever, +10 mails every 30 min
  python simulate_mail_arrival.py --interval 300 --batch-size 10
  python simulate_mail_arrival.py --once                # single batch, for cron/testing
"""

import argparse
import imaplib
import random
import time
from datetime import datetime

from seed_greenmail_dataset import (
    ANALYSTS,
    FOLDER_SPEC,
    IMAP_HOST,
    IMAP_PASSWORD,
    IMAP_PORT,
    IMAP_USER,
    build_forwarded_mail,
)

# Same relative weights as the initial bulk seed (FOLDER_SPEC's counts),
# so the ongoing trickle keeps the same realistic class imbalance instead
# of drifting towards a uniform distribution over time.
_FOLDERS = list(FOLDER_SPEC.keys())
_WEIGHTS = [count for _generator, count in FOLDER_SPEC.values()]


def ensure_folders(conn):
    """GreenMail (dev IMAP) is in-memory only - any container restart wipes
    every mailbox including the taxonomy folders, and conn.append() against a
    missing folder fails silently from this script's point of view (no
    exception, mail just never lands - see generator_dataset.py's own
    "Impossible d'ouvrir le dossier IMAP" warning on the read side). Recreate
    idempotently every run so a GreenMail restart self-heals instead of
    quietly starving the dataset."""
    status, existing = conn.list()
    existing_names = set()
    if status == "OK" and existing:
        for line in existing:
            decoded = line.decode() if isinstance(line, bytes) else line
            existing_names.add(decoded.rsplit(' "." ', 1)[-1].strip('"'))
    for folder in _FOLDERS:
        if folder not in existing_names:
            conn.create(f'"{folder}"')


def run_batch(conn, batch_size):
    ensure_folders(conn)
    added = []
    for _ in range(batch_size):
        folder = random.choices(_FOLDERS, weights=_WEIGHTS, k=1)[0]
        generator, _count = FOLDER_SPEC[folder]
        analyst = random.choice(ANALYSTS)
        sender, to, subject, body = generator()
        raw = build_forwarded_mail(analyst, folder, sender, to, subject, body)
        conn.append(f'"{folder}"', "", imaplib.Time2Internaldate(time.time()), raw)
        added.append(folder)
    return added


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--interval", type=int, default=1800,
                         help="secondes entre deux batches (défaut: 1800 = 30 min)")
    parser.add_argument("--batch-size", type=int, default=10,
                         help="nombre de mails ajoutés par batch (défaut: 10)")
    parser.add_argument("--once", action="store_true",
                         help="un seul batch puis quitte, au lieu de boucler indéfiniment")
    args = parser.parse_args()

    while True:
        conn = imaplib.IMAP4(IMAP_HOST, IMAP_PORT)
        conn.login(IMAP_USER, IMAP_PASSWORD)
        added = run_batch(conn, args.batch_size)
        conn.logout()

        counts = {}
        for folder in added:
            counts[folder] = counts.get(folder, 0) + 1
        print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] +{len(added)} mail(s): {counts}", flush=True)

        if args.once:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
