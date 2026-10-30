"""Read the mail body out of a case's mail archive (a tar with ``<ref>.txt`` and
``<ref>.headers`` members) without touching the disk.

The limits and the member rules mirror Analyzers/AIMailAnalyzer/mail_archive.py, which
extracts the same archive for the Cortex analyzer."""
from __future__ import annotations

import logging
import tarfile
import zlib
from pathlib import PurePosixPath

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


def read_archive_body(mail_archive) -> str | None:
    """The mail's ``.txt`` text, or None when the archive is missing, unreadable, unsafe,
    lacks a ``.txt`` or a ``.headers`` member, or the text is blank."""
    stored = getattr(mail_archive, "archive", None)
    if stored is None:
        return None
    try:
        with stored.file_path.open("rb") as handle, tarfile.open(fileobj=handle, mode="r:*") as tar:
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
