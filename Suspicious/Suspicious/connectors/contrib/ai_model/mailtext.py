"""Read a case's mail headers and body. The object store holds the durable copy
(``<mail_id>/<ref>.txt`` and ``.headers``); the submission's tar.gz on the work disk is only a
fallback, because tasp/cron/fetch_emails.py deletes it as soon as the handoff ends. The tar is read in memory,
never extracted, and its limits and member rules mirror Analyzers/AIMailAnalyzer/mail_archive.py,
which extracts the same archive for the Cortex analyzer."""
from __future__ import annotations

import email
import html.parser
import logging
import os
import tarfile
import zlib
from collections import defaultdict
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import PurePosixPath

from common.storage import StoreError, get_store
from connectors.contrib.thehive.utils import parse_and_decode_defaultdict
from connectors.providers import ProviderUnavailable
from mail_feeder.models import MailArchive
from score_process.scoring.cortex_analyzers.contrib.ai_minio_utils import (
    MAIL_TEXT_MAX_BYTES,
    fetch_mail_text_from_minio,
)

logger = logging.getLogger("connectors.contrib.ai_model")

MAX_MEMBERS = 1_000
MAX_TOTAL_BYTES = 200 * 1024 * 1024


@dataclass(frozen=True)
class MailMaterial:
    headers: str  # raw text of the .headers file
    text: str  # text of the .txt file


def header_dict(raw_headers: str) -> dict[str, list[str]]:
    """The headers keyed as the Cortex AI analyzer reported them (mail_archive.get_header_dict_list:
    every value of a key, in order), MIME encoded-words decoded as campaign detection read them."""
    # The analyzer read the file in text mode, so every line end it saw was "\n".
    raw_headers = raw_headers.replace("\r\n", "\n").replace("\r", "\n")
    collected = defaultdict(list)
    for key, value in email.message_from_string(raw_headers).items():
        collected[key].append(value)
    return parse_and_decode_defaultdict(str(collected))


def mail_archive_for(case) -> MailArchive | None:
    """The case's mail archive with its file and mail loaded; None when the case has no mail."""
    mail = getattr(case.fileOrMail, "mail", None)
    return MailArchive.objects.select_related("archive", "mail").filter(mail=mail).first() if mail else None


def _open_archive(stored):
    """Seekable binary handle on the archive. A submitted mail's tar.gz sits on the disk shared by
    the web and worker containers at ``File.tmp_path`` (the path the Cortex job is handed); its
    ``file_path`` is only the file's name. Fall back to the storage backend for an archive kept there
    (local, or the s3 backend, whose files are BytesIO-backed)."""
    path = getattr(stored, "tmp_path", "") or ""
    if os.path.isabs(path) and os.path.isfile(path):
        return open(path, "rb")
    return stored.file_path.open("rb")


def _mail_id(mail_archive) -> str:
    return str(getattr(getattr(mail_archive, "mail", None), "mail_id", "") or "")


def _read_object_store(mail_archive) -> tuple[str, str]:
    """The mail's (headers, text) from the object store, "" for a part it does not hold. The
    archive's ``bucket_name`` (the submission id) tells which layout to look in. Store errors
    propagate."""
    mail_id = _mail_id(mail_archive)
    if not mail_id:
        return "", ""
    bucket_name = str(getattr(mail_archive, "bucket_name", "") or "")
    return fetch_mail_text_from_minio(get_store(), mail_id, bucket_name)


def _material(headers: str, text: str) -> MailMaterial | None:
    return MailMaterial(headers, text) if headers.strip() and text.strip() else None


def read_archive_material(mail_archive) -> MailMaterial | None:
    """The mail's headers and text: from the object store, else from its tar archive. None when
    neither has a ``.txt`` and a ``.headers`` that are both non-blank. ProviderUnavailable when the
    store failed and the archive cannot stand in (an outage must not become a verdict); retryable
    unless the store answered access_denied or invalid."""
    store_error = label = None
    try:
        material = _material(*_read_object_store(mail_archive))
    except Exception as exc:  # noqa: BLE001 -- the store client's failures are many; the label is reported
        # A StoreError code is a fixed word; anything else gets its class name. Never the message,
        # which can carry the endpoint or a key.
        store_error, material = exc, None
        label = exc.code if isinstance(exc, StoreError) else type(exc).__name__
        logger.warning("object store read failed for mail %s: %s", _mail_id(mail_archive), label)
    if material is None:
        material = _material(*_read_tar(mail_archive))
    if material is None and store_error is not None:
        # Denied and invalid will not change on a retry; an outage or an unknown error may.
        permanent = isinstance(store_error, StoreError) and store_error.code in ("access_denied", "invalid")
        raise ProviderUnavailable(f"object store unavailable: {label}", retryable=not permanent) from store_error
    return material


def read_archive_body(mail_archive) -> str | None:
    """The text of read_archive_material, under the same rules."""
    material = read_archive_material(mail_archive)
    return material.text if material else None


# What a damaged or hostile archive raises out of open_safe_tar.
TAR_ERRORS = (tarfile.TarError, OSError, EOFError, zlib.error, ValueError)


@contextmanager
def open_safe_tar(stored):
    """Yield (tar, files): the open archive of ``stored`` (a File) and its regular-file members as
    (relative path, TarInfo), never extracted. Raises ValueError (or another TAR_ERRORS) for more
    than MAX_MEMBERS entries, more than MAX_TOTAL_BYTES once uncompressed, an entry that is neither
    a regular file nor a directory, or an absolute name or one with a ``..`` part."""
    with _open_archive(stored) as handle, tarfile.open(fileobj=handle, mode="r:*") as tar:
        members = tar.getmembers()
        if len(members) > MAX_MEMBERS:
            raise ValueError(f"archive has too many entries ({len(members)})")
        if sum(max(m.size, 0) for m in members) > MAX_TOTAL_BYTES:
            raise ValueError("archive is too large once uncompressed")
        files = []
        for member in members:
            if not (member.isreg() or member.isdir()):
                raise ValueError(f"archive has an unsupported entry type: {member.name}")
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError(f"archive entry escapes the archive: {member.name}")
            if member.isreg():
                files.append((path, member))
        yield tar, files


def _read_tar(mail_archive) -> tuple[str, str]:
    """The (headers, text) of the mail's tar archive's ``.headers`` and ``.txt`` members; ("", "")
    when it is missing, unreadable, unsafe, or lacks either member."""
    stored = getattr(mail_archive, "archive", None)
    if stored is None:
        return "", ""
    try:
        with open_safe_tar(stored) as (tar, files):
            body = head = None
            for path, member in files:
                if len(path.parts) != 1:
                    continue
                if path.name.endswith(".txt") and body is None:
                    body = member
                elif path.name.endswith(".headers") and head is None:
                    head = member
            if body is None or head is None:
                return "", ""
            # Capped like the store read: a worker killed on memory would get this message again.
            headers, text = (
                tar.extractfile(member).read(MAIL_TEXT_MAX_BYTES).decode("utf-8", errors="replace")
                for member in (head, body)
            )
    except TAR_ERRORS as exc:
        # The class only: the message names archive members, which are the mail's file names.
        logger.warning("mail archive %s not readable: %s", getattr(stored, "pk", "?"), type(exc).__name__)
        return "", ""
    return headers, text


class _TextOnly(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts, self._skip = [], 0

    def handle_starttag(self, tag, attrs):
        self._skip += tag in ("script", "style")

    def handle_endtag(self, tag):
        self._skip = max(0, self._skip - (tag in ("script", "style")))

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)


def text_from_message(message) -> str:
    """The plain part of an EmailMessage (policy=default), else its HTML part reduced to text; "" when
    neither is usable."""
    for kind in ("plain", "html"):
        part = message.get_body(preferencelist=(kind,))
        if part is None:
            continue
        try:
            text = part.get_content()
        except (LookupError, ValueError, UnicodeError, AttributeError):
            # Undecodable charset: keep the part, decoding its raw payload with replacement.
            try:
                text = (part.get_payload(decode=True) or b"").decode("utf-8", errors="replace")
            except (LookupError, ValueError, UnicodeError, AttributeError):
                continue
        if kind == "html":
            parser = _TextOnly()
            parser.feed(text)
            parser.close()
            text = " ".join(" ".join(parser.parts).split())
        text = text.strip()
        if text:
            return text
    return ""
