"""What a campaign alert is built from: the reported mail's stored files, and
which of its attachments are worth putting in front of an analyst."""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field

from common.storage import StoreError
from score_process.scoring.cortex_analyzers.contrib.ai_minio_utils import (
    _read_object_safe,
    find_mail_prefix,
)

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")

MAX_FILE_BYTES = 10 * 1024 * 1024
# A tracking pixel or a signature logo carries no evidence; real scans and
# screenshots are larger than this.
_TINY_IMAGE_BYTES = 2048
_IMAGE_MAGIC = (b"\x89PNG", b"GIF8", b"\xff\xd8\xff", b"BM")


@dataclass
class Attachment:
    name: str
    data: bytes

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()


@dataclass
class MailMaterial:
    headers: str = ""
    text: str = ""
    html: str = ""
    eml: bytes = b""
    attachments: list[Attachment] = field(default_factory=list)


def _put(material: MailMaterial, rel: str, data: bytes) -> None:
    if rel.startswith("attachments/"):
        material.attachments.append(Attachment(rel[len("attachments/"):], data))
    elif rel.endswith(".headers"):
        material.headers = data.decode("utf-8", "replace")
    elif rel.endswith(".txt"):
        material.text = data.decode("utf-8", "replace")
    elif rel.endswith(".html"):
        material.html = data.decode("utf-8", "replace")
    elif rel.endswith(".eml"):
        material.eml = data


def _from_tar(mail_id: str, mail_archive) -> MailMaterial | None:
    """The material in the submission's tar (mailtext's safety rules), None when there is no tar or
    it is refused. Root files and ``attachments/``; a file named after the mail wins over another of
    its kind (a web upload's tar also holds the uploaded ``user_submission.eml``)."""
    from connectors.contrib.ai_model.mailtext import TAR_ERRORS, open_safe_tar

    stored = getattr(mail_archive, "archive", None)
    if stored is None:
        return None
    material = MailMaterial()
    try:
        with open_safe_tar(stored) as (tar, files):
            for path, member in sorted(files, key=lambda f: f[0].stem == mail_id):
                if len(path.parts) == 1 or (len(path.parts) > 1 and path.parts[0] == "attachments"):
                    # One byte past the cap, so select_attachments still sees it as too large.
                    _put(material, str(path), tar.extractfile(member).read(MAX_FILE_BYTES + 1))
    except TAR_ERRORS as exc:
        # The class only: the message names archive members, which are the mail's file names.
        logger.warning("campaign material: archive of mail %s refused: %s", mail_id, type(exc).__name__)
        return None
    return material


def fetch_mail_material(client, mail_id: str, bucket_name: str = "", mail_archive=None) -> MailMaterial:
    """Read the mail's stored parts and attachments; empty material if not found.
    ``bucket_name`` is the mail's ``MailArchive.bucket_name`` (see find_mail_prefix). When the store
    has no location for the mail (a web upload's prefix is not recorded), ``mail_archive``'s tar
    stands in. Remaining limit: a web upload whose tar can no longer be read gives empty material."""
    location = find_mail_prefix(client, mail_id, bucket_name)
    if not location:
        material = _from_tar(mail_id, mail_archive)
        if material is None:
            logger.warning("campaign material: no bucket holds mail %s", mail_id)
            return MailMaterial()
        return material
    material = MailMaterial()
    bucket, prefix = location
    for obj in client.list(bucket, prefix=prefix, recursive=True):
        try:
            data = _read_object_safe(client, bucket, obj.name)
        except StoreError as exc:
            if exc.code != "not_found":
                raise
            # Never the object name or message: the name is the mail's file name.
            logger.warning("campaign material: an object of mail %s vanished: %s", mail_id, exc.code)
            continue
        except Exception as exc:  # noqa: BLE001 — one unreadable object must not lose the rest
            logger.warning("campaign material: cannot read an object of mail %s: %s", mail_id, type(exc).__name__)
            continue
        _put(material, obj.name[len(prefix):], data)
    return material


def _is_tiny_image(data: bytes) -> bool:
    return len(data) <= _TINY_IMAGE_BYTES and data.startswith(_IMAGE_MAGIC)


def select_attachments(attachments):
    """Split into (kept, skipped). skipped items are (name, sha256, size, reason)."""
    kept: list[Attachment] = []
    skipped: list[tuple[str, str, int, str]] = []
    seen: dict[str, str] = {}
    for att in attachments:
        size, sha = len(att.data), att.sha256
        if size == 0:
            reason = "empty"
        elif _is_tiny_image(att.data):
            reason = "tracking-pixel-sized image"
        elif size > MAX_FILE_BYTES:
            reason = f"too large ({size // (1024 * 1024)} MB)"
        elif sha in seen:
            reason = f"duplicate of {seen[sha]}"
        else:
            seen[sha] = att.name
            kept.append(att)
            continue
        skipped.append((att.name, sha, size, reason))
    return kept, skipped
