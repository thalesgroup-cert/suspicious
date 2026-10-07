"""What a campaign alert is built from: the reported mail's stored files, and
which of its attachments are worth putting in front of an analyst."""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field

from score_process.scoring.cortex_analyzers.contrib.ai_minio_utils import (
    _find_mail_bucket,
    _read_object_safe,
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


def fetch_mail_material(client, mail_id: str) -> MailMaterial:
    """Read the mail's stored parts and attachments; empty material if not found."""
    material = MailMaterial()
    bucket = _find_mail_bucket(client, mail_id)
    if not bucket:
        logger.warning("campaign material: no bucket holds mail %s", mail_id)
        return material
    prefix = f"{mail_id}/"
    for obj in client.list_objects(bucket, prefix=prefix, recursive=True):
        rel = obj.object_name[len(prefix):]
        try:
            data = _read_object_safe(client, bucket, obj.object_name)
        except Exception as exc:  # noqa: BLE001 — one unreadable object must not lose the rest
            logger.warning("campaign material: cannot read %s: %s", obj.object_name, exc)
            continue
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
