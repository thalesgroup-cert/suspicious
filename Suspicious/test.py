#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import ast
import email
import imaplib
import pathlib
import hashlib
import mimetypes
import logging
import django
import re
from datetime import datetime, timedelta
from email import policy
from email.header import decode_header
from base64 import b64encode

# ================= CONFIG =================

IMAP_HOST = "host"
IMAP_PORT = 993
IMAP_LOGIN = "login"
IMAP_PASSWORD = "password"

OUTPUT_DIR = pathlib.Path("/app/output")

MAILBOXES = [
    "INBOX",
    "Archive",
    "3_bad",
    "2_WHALING_PHISHING",
    "2_CLONE_PHISHING",
    "2_CLASSIC_PHISHING",
    "2_BLACKMAILING_PHISHING",
    "1_SPAM",
    "1_NEWSLETTER",
    "0_LEGIT_INTERNAL_COMMUNICATION",
    "0_LEGIT_EXTERNAL_COMMUNICATION",
]

DATE_WINDOW_MINUTES = 120  # fallback window

# ================= LOGGING =================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

# ================= IMAP UTILS =================

def imap_utf7(s: str) -> str:
    res, buf = [], []

    def flush():
        if buf:
            b = "".join(buf).encode("utf-16-be")
            res.append("&" + b64encode(b).decode().rstrip("=").replace("/", ",") + "-")
            buf.clear()

    for c in s:
        if 0x20 <= ord(c) <= 0x7E and c != "&":
            flush()
            res.append(c)
        elif c == "&":
            flush()
            res.append("&-")
        else:
            buf.append(c)
    flush()
    return "".join(res)


def connect_imap():
    imap = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
    imap.login(IMAP_LOGIN, IMAP_PASSWORD)
    return imap


# ================= HEADER UTILS =================

def parse_header_dict(raw):
    if isinstance(raw, dict):
        return raw
    try:
        obj = ast.literal_eval(raw)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def normalize_subject(raw: str | None) -> str | None:
    if not raw:
        return None

    decoded = decode_header(raw)
    subject = "".join(
        part.decode(enc or "utf-8", errors="ignore") if isinstance(part, bytes) else part
        for part, enc in decoded
    )

    subject = subject.lower()
    subject = re.sub(r"^(re|fw|fwd|tr)\s*[:\]]\s*", "", subject)
    subject = re.sub(r"\s+", " ", subject).strip()

    return subject or None


def parse_date(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        return email.utils.parsedate_to_datetime(raw)
    except Exception:
        return None


# ================= MATCHING =================

def headers_match(msg, ref):
    """Final safety check"""
    if ref["subject"]:
        if normalize_subject(msg.get("Subject")) != ref["subject"]:
            return False

    if ref["from"]:
        if ref["from"].lower() not in (msg.get("From") or "").lower():
            return False

    return True


# ================= SEARCH =================

def search_by_message_id(imap, mailbox, msgid):
    status, data = imap.uid(
        "SEARCH",
        None,
        f'(HEADER Message-ID "{msgid.strip("<>")}")'
    )
    return data[0].split() if status == "OK" and data and data[0] else []


def search_by_subject_and_date(imap, mailbox, subject, ref_date):
    since = (ref_date - timedelta(minutes=DATE_WINDOW_MINUTES)).strftime("%d-%b-%Y")
    status, data = imap.uid(
        "SEARCH",
        None,
        f'(SINCE {since} SUBJECT "{subject}")'
    )
    return data[0].split() if status == "OK" and data and data[0] else []


def fetch_message(imap, uid):
    status, data = imap.uid("FETCH", uid, "(RFC822)")
    if status != "OK" or not data or not data[0]:
        return None
    return email.message_from_bytes(data[0][1], policy=policy.default)


# ================= EXPORT =================

def save_eml(msg, case_id):
    base = OUTPUT_DIR / f"case_{case_id}"
    base.mkdir(parents=True, exist_ok=True)

    (base / "original.eml").write_bytes(msg.as_bytes())

    att_dir = base / "attachments"
    att_dir.mkdir(exist_ok=True)

    for part in msg.iter_attachments():
        payload = part.get_payload(decode=True)
        if not payload:
            continue

        name = part.get_filename() or "attachment.bin"
        digest = hashlib.sha256(payload).hexdigest()[:12]
        (att_dir / f"{digest}_{name}").write_bytes(payload)


# ================= MAIN =================

def main():
    imap = connect_imap()
    log.info("IMAP connected")

    from case_handler.models import Case

    cases = Case.objects.filter(is_challenged=True)

    for case in cases:
        raw = getattr(case.fileOrMail.mail.mail_header, "header_value", None)
        headers = parse_header_dict(raw)

        ref = {
            "message_id": headers.get("Message-ID"),
            "subject": normalize_subject(headers.get("Subject")),
            "date": parse_date(headers.get("Date")),
            "from": headers.get("From"),
        }

        found = False

        for mailbox in MAILBOXES:
            imap.select(imap_utf7(mailbox), readonly=True)

            # 1️⃣ Message-ID
            if ref["message_id"]:
                uids = search_by_message_id(imap, mailbox, ref["message_id"])
                for uid in uids:
                    msg = fetch_message(imap, uid)
                    if msg and headers_match(msg, ref):
                        save_eml(msg, case.id)
                        log.info(f"Case {case.id} resolved by Message-ID")
                        found = True
                        break

            if found:
                break

            # 2️⃣ Fallback
            if ref["subject"] and ref["date"]:
                uids = search_by_subject_and_date(imap, mailbox, ref["subject"], ref["date"])
                for uid in uids:
                    msg = fetch_message(imap, uid)
                    if msg and headers_match(msg, ref):
                        save_eml(msg, case.id)
                        log.info(f"Case {case.id} resolved by Subject fallback")
                        found = True
                        break

            if found:
                break

        if not found:
            log.warning(f"Case {case.id}: not found")

    imap.logout()


# ================= ENTRY =================

if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "suspicious.settings")
    django.setup()
    main()
