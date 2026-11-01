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
_UID = re.compile(rb"\bUID (\d+)")
_SIZE = re.compile(rb"\bRFC822\.SIZE (\d+)")


class FolderUnavailable(Exception):
    """This folder cannot be read (bad name, missing, refused, SEARCH failed); others may still be."""


class ImapConnectionLost(Exception):
    """The connection broke (abort, socket error, timeout): fatal for the whole run."""


class ImapLoginFailed(Exception):
    """connect() could not log in. The message is the original exception's class name only: server
    login answers can echo the user, the password or a banner. Fatal for the run, like a lost
    connection, but a retry will not help until the credentials are fixed."""

    retryable = False  # run_sync_now records the failure without retrying


class ImapTlsFailed(Exception):
    """The TLS handshake or the certificate check failed. The message is the exception class name
    only. Fatal for the run and not retried: an untrusted certificate (an internal CA missing from
    the container's trust store) or a TLS mismatch needs an operator."""

    retryable = False


def _shown(folder: str) -> str:
    """The folder name for errors and logs: ascii() form, at most 64 characters."""
    return ascii(folder)[:64]


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
    inner_message_ids: tuple[str, ...] = ()


def connect(host, port, user, password, use_ssl, timeout=30):
    """A logged-in IMAP4_SSL (certificate verified against the system CA store) or IMAP4 client;
    ImapTlsFailed on a TLS or certificate failure, ImapLoginFailed on login."""
    if use_ssl:
        try:
            client = imaplib.IMAP4_SSL(host, port, ssl_context=ssl.create_default_context(), timeout=timeout)
        except (ssl.SSLError, ssl.CertificateError) as exc:  # the server's text stays out
            raise ImapTlsFailed(type(exc).__name__) from None
    else:
        client = imaplib.IMAP4(host, port, timeout=timeout)
    try:
        client.login(user, password)
    except Exception as exc:
        client.shutdown()
        raise ImapLoginFailed(type(exc).__name__) from None
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


def _new_uids(imap, folder: str, since_uid: int, limit: int) -> list[int]:
    try:
        typ, data = imap.uid("SEARCH", None, "UID", f"{since_uid + 1}:*")
    except imaplib.IMAP4.abort:
        raise
    except imaplib.IMAP4.error:
        raise FolderUnavailable(_shown(folder)) from None
    if typ != "OK":
        raise FolderUnavailable(_shown(folder))
    joined = b" ".join(d for d in data or () if isinstance(d, bytes))
    # "n:*" answers the last UID even when none is newer: filter ourselves. Lowest first so the
    # caller's checkpoint advances monotonically.
    return sorted(u for u in {int(x) for x in re.findall(rb"\d+", joined)} if u > since_uid)[:limit]


def _oversize(imap, uids: list[int]) -> set[int]:
    """UIDs the server reports above the cap, asked once for the batch. Empty when it refuses."""
    try:
        typ, data = imap.uid("FETCH", ",".join(map(str, uids)), "(RFC822.SIZE)")
    except imaplib.IMAP4.abort:
        raise
    except imaplib.IMAP4.error:
        return set()  # the post-download check still applies
    found = set()
    for item in (data or ()) if typ == "OK" else ():
        line = item[0] if isinstance(item, tuple) else item
        uid, size = _UID.search(line or b""), _SIZE.search(line or b"")
        if uid and size and int(size.group(1)) > MAX_MESSAGE_BYTES:
            found.add(int(uid.group(1)))
    return found


def _fetch(imap, uid: int) -> bytes | None:
    """The raw message, or None when the server refuses it, the answer has no literal or it is above
    the size cap."""
    # ponytail: backstop for servers whose RFC822.SIZE is missing or wrong; imaplib has already read
    # the whole literal by then (no streaming), so the precheck in _oversize is the real guard.
    try:
        typ, data = imap.uid("FETCH", str(uid), "(BODY.PEEK[])")
    except imaplib.IMAP4.abort:
        raise
    except imaplib.IMAP4.error:
        return None
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


class UidValidityChanged(Exception):
    """fetch_one: the folder's UIDVALIDITY is not the one the UID was recorded under."""


def fetch_one(imap, folder, uidvalidity, uid) -> ReviewMail | None:
    """The ReviewMail at one UID, read-only like read_folder; None when it is gone, refused, above
    the size cap or not a forward. UidValidityChanged when the folder's UIDVALIDITY differs (the UID
    then names another mail). FolderUnavailable / ImapConnectionLost as read_folder."""
    try:
        _select(imap, folder)
        if _uidvalidity(imap) != uidvalidity:
            raise UidValidityChanged(_shown(folder))
        raw = None if _oversize(imap, [uid]) else _fetch(imap, uid)
        try:
            return _review_mail(raw, folder, uidvalidity, uid) if raw else None
        except Exception as exc:  # untrusted mail: any parse failure is "no mail"
            logger.info("ai_model imap: unreadable mail in %s (%s)", _shown(folder), type(exc).__name__)
            return None
    except (imaplib.IMAP4.abort, OSError) as exc:
        raise ImapConnectionLost(type(exc).__name__) from None


def _date(value) -> datetime | None:
    """The Date header as an aware datetime; a naive one (no zone, or -0000) is taken as UTC. None
    when missing or unparseable."""
    try:
        parsed = parsedate_to_datetime(str(value)) if value else None
    except (TypeError, ValueError, IndexError):
        return None
    if parsed is not None and parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _review_mail(raw: bytes, folder: str, uidvalidity: int, uid: int) -> ReviewMail | None:
    """The labelled mail is the FIRST message/rfc822 part in document order (depth-first), so the
    outermost forward wins and later sibling attachments are ignored. Message/rfc822 parts nested
    inside it only contribute their Message-IDs to `inner_message_ids`, a match fallback."""
    outer = email.message_from_bytes(raw, policy=policy.default)
    part = next((p for p in outer.walk() if p.get_content_type() == "message/rfc822"), None)
    if part is None:
        return None
    message = part.get_content()
    nested = (p.get_payload(0) for p in message.walk() if p.get_content_type() == "message/rfc822")
    return ReviewMail(
        folder=folder,
        uidvalidity=uidvalidity,
        uid=uid,
        message_id=normalise(str(message.get("Message-ID", ""))),
        sender=parseaddr(str(message.get("From", "")))[1].strip().lower(),
        date=_date(message.get("Date")),
        subject=str(message.get("Subject", "")).strip(),
        text=text_from_message(message),
        inner_message_ids=tuple(i for i in (normalise(str(m.get("Message-ID", ""))) for m in nested) if i),
    )


def _quoted(folder: str) -> str:
    """An IMAP quoted string: imaplib sends the mailbox as given, so spaces would break SELECT.

    Refuses control characters, DEL and non-ASCII: a CR/LF would end the command and let the name
    inject another one. The exception names the folder through ascii(), never raw.
    """
    bad = next((i for i, c in enumerate(folder) if ord(c) < 0x20 or ord(c) >= 0x7F), None)
    if bad is not None:
        raise FolderUnavailable(f"{_shown(folder)}: forbidden character at index {bad}")
    return '"' + folder.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _select(imap, folder: str) -> None:
    quoted = _quoted(folder)
    try:
        typ, _ = imap.select(quoted, readonly=True)
    except imaplib.IMAP4.readonly as exc:  # a subclass of abort, but about this folder only
        logger.warning("ai_model imap: cannot select %s (%s)", _shown(folder), type(exc).__name__)
        raise FolderUnavailable(_shown(folder)) from None
    except imaplib.IMAP4.abort:
        raise
    except imaplib.IMAP4.error as exc:
        logger.warning("ai_model imap: cannot select %s (%s)", _shown(folder), type(exc).__name__)
        raise FolderUnavailable(_shown(folder)) from None
    if typ != "OK":
        logger.warning("ai_model imap: cannot select %s (%s)", _shown(folder), typ)
        raise FolderUnavailable(_shown(folder))


def read_folder(imap, folder, *, since_uid, limit, known_uidvalidity=None):
    """(mails, skipped, uidvalidity, last_uid) for the lowest `limit` UIDs above `since_uid`.

    A mail with no message/rfc822 part, an unreadable or refused one and one above 25 MB count in
    `skipped`. `last_uid` is the highest UID examined, skipped ones included (`since_uid` when none
    is newer). When `known_uidvalidity` is given and differs from the folder's, the read starts from
    UID 0. FolderUnavailable: this folder only. ImapConnectionLost: the connection is gone.
    """
    try:
        return _read_folder(imap, folder, since_uid, limit, known_uidvalidity)
    except (imaplib.IMAP4.abort, OSError) as exc:  # TimeoutError and ssl errors are OSErrors
        logger.warning("ai_model imap: connection lost reading %s (%s)", _shown(folder), type(exc).__name__)
        raise ImapConnectionLost(type(exc).__name__) from None


def _read_folder(imap, folder, since_uid, limit, known_uidvalidity):
    _select(imap, folder)
    uidvalidity = _uidvalidity(imap)
    if known_uidvalidity is not None and known_uidvalidity != uidvalidity:
        since_uid = 0
    mails, skipped = [], 0
    uids = _new_uids(imap, folder, since_uid, limit)
    oversize = _oversize(imap, uids) if uids else set()
    for uid in uids:
        raw = None if uid in oversize else _fetch(imap, uid)
        try:
            mail = _review_mail(raw, folder, uidvalidity, uid) if raw else None
        except Exception as exc:  # untrusted mail: any parse failure is one skipped mail
            logger.info("ai_model imap: skipped a mail in %s (%s)", _shown(folder), type(exc).__name__)
            mail = None
        if mail is None:
            skipped += 1
        else:
            mails.append(mail)
    return mails, skipped, uidvalidity, (uids[-1] if uids else since_uid)
