"""Read a case's mail body. The object store holds the durable copy (``<mail_id>/<ref>.txt`` and
``.headers``); the submission's tar.gz on the work disk is only a fallback, because
tasp/cron/fetch_emails.py deletes it as soon as the handoff ends. The tar is read in memory,
never extracted, and its limits and member rules mirror Analyzers/AIMailAnalyzer/mail_archive.py,
which extracts the same archive for the Cortex analyzer."""
from __future__ import annotations

import logging
import os
import tarfile
import zlib
from pathlib import PurePosixPath

from common.storage import StoreError, get_store
from connectors.providers import ProviderUnavailable
from score_process.scoring.cortex_analyzers.contrib.ai_minio_utils import fetch_mail_text_from_minio

logger = logging.getLogger("connectors.contrib.ai_model")

MAX_MEMBERS = 1_000
MAX_TOTAL_BYTES = 200 * 1024 * 1024


def _top_level_name(name: str) -> str | None:
    """The member's name when it sits at the archive root ("./m.txt" counts), else None.
    Raises ValueError for an absolute name or one with a ``..`` part."""
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"archive entry escapes the archive: {name}")
    return path.name if len(path.parts) == 1 else None


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


def _read_object_store(mail_archive) -> str | None:
    """The mail's text from the object store; None when it has no ``.txt`` and ``.headers`` there
    or the text is blank. The archive's ``bucket_name`` (the submission id) tells which layout to
    look in. Store errors propagate."""
    mail_id = _mail_id(mail_archive)
    if not mail_id:
        return None
    bucket_name = str(getattr(mail_archive, "bucket_name", "") or "")
    headers, text = fetch_mail_text_from_minio(get_store(), mail_id, bucket_name)
    return text if headers.strip() and text.strip() else None


def read_archive_body(mail_archive) -> str | None:
    """The mail's text: from the object store, else from its tar archive. None when neither has a
    ``.txt`` and a ``.headers`` with a non-blank text. ProviderUnavailable (retryable) when the
    store failed and the archive cannot stand in: an outage must not become a verdict."""
    store_error = None
    try:
        text = _read_object_store(mail_archive)
    except Exception as exc:  # noqa: BLE001 -- the store client's failures are many; the label is reported
        store_error, text = exc, None
        logger.warning(
            "object store read failed for mail %s: %s: %s", _mail_id(mail_archive), type(exc).__name__, exc
        )
    if text is None:
        text = _read_tar(mail_archive)
    if text is None and store_error is not None:
        # A StoreError code is a fixed word; anything else gets its class name. Never the message,
        # which can carry the endpoint or a key.
        label = store_error.code if isinstance(store_error, StoreError) else type(store_error).__name__
        raise ProviderUnavailable(f"object store unavailable: {label}") from store_error
    return text


def _read_tar(mail_archive) -> str | None:
    """The ``.txt`` text of the mail's tar archive, or None when it is missing, unreadable, unsafe,
    lacks a ``.txt`` or a ``.headers`` member, or the text is blank."""
    stored = getattr(mail_archive, "archive", None)
    if stored is None:
        return None
    try:
        with _open_archive(stored) as handle, tarfile.open(fileobj=handle, mode="r:*") as tar:
            members = tar.getmembers()
            if len(members) > MAX_MEMBERS:
                raise ValueError(f"archive has too many entries ({len(members)})")
            if sum(max(m.size, 0) for m in members) > MAX_TOTAL_BYTES:
                raise ValueError("archive is too large once uncompressed")
            body = has_headers = None
            for member in members:
                if not (member.isreg() or member.isdir()):
                    raise ValueError(f"archive has an unsupported entry type: {member.name}")
                name = _top_level_name(member.name)
                if not member.isreg() or name is None:
                    continue
                if name.endswith(".txt") and body is None:
                    body = member
                elif name.endswith(".headers"):
                    has_headers = True
            if body is None or not has_headers:
                return None
            text = tar.extractfile(body).read().decode("utf-8", errors="replace")
    except (tarfile.TarError, OSError, EOFError, zlib.error, ValueError) as exc:
        logger.warning("mail archive %s not readable: %s", getattr(stored, "pk", "?"), exc)
        return None
    return text if text.strip() else None
