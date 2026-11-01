"""Read the analysts' review folders over IMAP, read-only (Plan D, Task 4).

Each review mail is an analyst's forward: the reviewed mail rides inside it as a message/rfc822
attachment. Only that inner message is read. The mailbox is selected read-only and fetched with
BODY.PEEK[], so nothing is flagged, moved or deleted. Logs and exceptions carry the exception class
and the folder name, never mail data or credentials.
"""
from __future__ import annotations

import email
import imaplib
import logging
import re
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from email import policy
from email.utils import parseaddr, parsedate_to_datetime

from ai_model.messageid import normalise
from connectors.contrib.ai_model.mailtext import text_from_message

logger = logging.getLogger(__name__)

MAX_MESSAGE_BYTES = 25 * 1024 * 1024
_LITERAL_SIZE = re.compile(rb"\{(\d+)\}\s*$")


class FolderUnavailable(Exception):
    """The folder could not be selected (missing, or refused by the server)."""


@dataclass(frozen=True)
class ReviewMail:
    folder: str
    uidvalidity: int
    uid: int
    message_id: str
    sender: str
    date: datetime | None
    subject: str
    text: str


def connect(host, port, user, password, use_ssl, timeout=30):
    """A logged-in IMAP4_SSL (certificate verified) or IMAP4 client. Login errors propagate."""
    if use_ssl:
        client = imaplib.IMAP4_SSL(host, port, ssl_context=ssl.create_default_context(), timeout=timeout)
    else:
        client = imaplib.IMAP4(host, port, timeout=timeout)
    try:
        client.login(user, password)
    except BaseException:
        client.shutdown()
        raise
    return client


def _uidvalidity(imap) -> int:
    _, data = imap.response("UIDVALIDITY")
    try:
        return int(data[0])
    except (TypeError, ValueError, IndexError):
        return 0


def _new_uids(imap, since_uid: int, limit: int) -> list[int]:
    typ, data = imap.uid("SEARCH", None, "UID", f"{since_uid + 1}:*")
    if typ != "OK" or not data or not data[0]:
        return []
    # "n:*" answers the last UID even when none is newer: filter ourselves. Lowest first so the
    # caller's checkpoint advances monotonically.
    return sorted(u for u in {int(x) for x in data[0].split()} if u > since_uid)[:limit]


def _fetch(imap, uid: int) -> bytes | None:
    """The raw message, or None when the answer has no literal or it is above the size cap."""
    # ponytail: imaplib reads the whole literal before the cap applies (no streaming); a prior
    # UID FETCH (RFC822.SIZE) would avoid downloading oversize mails.
    typ, data = imap.uid("FETCH", str(uid), "(BODY.PEEK[])")
    if typ != "OK":
        return None
    literal = next((item for item in data or () if isinstance(item, tuple) and len(item) == 2), None)
    if literal is None:
        return None
    head, raw = literal
    size = _LITERAL_SIZE.search(head or b"")
    if (int(size.group(1)) if size else len(raw or b"")) > MAX_MESSAGE_BYTES:
        return None
    return raw if isinstance(raw, bytes) else None


def _date(value) -> datetime | None:
    try:
        parsed = parsedate_to_datetime(str(value)) if value else None
    except (TypeError, ValueError, IndexError):
        return None
    if parsed is not None and parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _review_mail(raw: bytes, folder: str, uidvalidity: int, uid: int) -> ReviewMail | None:
    outer = email.message_from_bytes(raw, policy=policy.default)
    part = next((p for p in outer.walk() if p.get_content_type() == "message/rfc822"), None)
    if part is None:
        return None
    message = part.get_content()
    return ReviewMail(
        folder=folder,
        uidvalidity=uidvalidity,
        uid=uid,
        message_id=normalise(str(message.get("Message-ID", ""))),
        sender=parseaddr(str(message.get("From", "")))[1].strip().lower(),
        date=_date(message.get("Date")),
        subject=str(message.get("Subject", "")).strip(),
        text=text_from_message(message),
    )


def _quoted(folder: str) -> str:
    """An IMAP quoted string: imaplib sends the mailbox as given, so spaces would break SELECT."""
    return '"' + folder.replace("\\", "\\\\").replace('"', '\\"') + '"'


def read_folder(imap, folder, *, since_uid, limit, known_uidvalidity=None):
    """(mails, skipped, uidvalidity, last_uid) for the lowest `limit` UIDs above `since_uid`.

    A mail with no message/rfc822 part, an unreadable one and one above 25 MB count in `skipped`.
    `last_uid` is the highest UID examined, skipped ones included (`since_uid` when none is newer).
    When `known_uidvalidity` is given and differs from the folder's, the read starts from UID 0.
    """
    try:
        typ, _ = imap.select(_quoted(folder), readonly=True)
    except imaplib.IMAP4.error as exc:
        logger.warning("ai_model imap: cannot select %s (%s)", folder, type(exc).__name__)
        raise FolderUnavailable(folder) from None
    if typ != "OK":
        logger.warning("ai_model imap: cannot select %s (%s)", folder, typ)
        raise FolderUnavailable(folder)
    uidvalidity = _uidvalidity(imap)
    if known_uidvalidity is not None and known_uidvalidity != uidvalidity:
        since_uid = 0
    mails, skipped = [], 0
    uids = _new_uids(imap, since_uid, limit)
    for uid in uids:
        raw = _fetch(imap, uid)
        try:
            mail = _review_mail(raw, folder, uidvalidity, uid) if raw else None
        except Exception as exc:  # untrusted mail: any parse failure is one skipped mail
            logger.info("ai_model imap: skipped a mail in %s (%s)", folder, type(exc).__name__)
            mail = None
        if mail is None:
            skipped += 1
        else:
            mails.append(mail)
    return mails, skipped, uidvalidity, (uids[-1] if uids else since_uid)
