"""MinIO-backed storage for uploaded avatar photos.

Deliberately not sharing case_handler's MinioManager (mail/case-artifact
specific) — profiles has no business importing that app's internals, so
this talks to the shared common.clients.get_s3_client() MinIO client
directly, same as tasp.cron.fetch_emails and mail_feeder do.
"""
from __future__ import annotations

import io
import logging
import uuid
from datetime import timedelta

from PIL import Image, UnidentifiedImageError

from common.clients import get_s3_client
from settings.config import get_section

logger = logging.getLogger(__name__)

DEFAULT_AVATAR_BUCKET = "suspicious-avatars"
AVATAR_MAX_BYTES = 2 * 1024 * 1024
AVATAR_ALLOWED_CONTENT_TYPES = {"image/jpeg", "image/png", "image/webp"}
AVATAR_DIMENSION = 512
AVATAR_URL_EXPIRES = timedelta(hours=1)


class InvalidAvatarImage(Exception):
    """Raised when an uploaded file fails format/size/decode validation."""


def _avatar_bucket_name() -> str:
    try:
        return (get_section("storage.s3") or {}).get("avatars_bucket") or DEFAULT_AVATAR_BUCKET
    except Exception as exc:
        logger.warning(f"Failed to read avatars_bucket from config: {exc}. Using default: {DEFAULT_AVATAR_BUCKET}")
        return DEFAULT_AVATAR_BUCKET


def _ensure_bucket(client, bucket_name: str) -> None:
    if not client.bucket_exists(bucket_name):
        client.make_bucket(bucket_name)


def process_avatar_image(content_type: str, size: int, raw: bytes) -> bytes:
    """Validate + center-crop + resize + re-encode an uploaded avatar.

    Raises InvalidAvatarImage on any validation failure. Returns JPEG
    bytes ready to store — the re-encode is also what strips EXIF, since
    Pillow does not carry source metadata into a freshly-encoded output.
    """
    if content_type not in AVATAR_ALLOWED_CONTENT_TYPES:
        raise InvalidAvatarImage(f"Unsupported content type: {content_type!r}")
    if size > AVATAR_MAX_BYTES:
        raise InvalidAvatarImage(f"File too large: {size} bytes (max {AVATAR_MAX_BYTES})")

    try:
        Image.open(io.BytesIO(raw)).verify()
        image = Image.open(io.BytesIO(raw)).convert("RGB")
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError) as exc:
        raise InvalidAvatarImage("File is not a valid image") from exc

    width, height = image.size
    side = min(width, height)
    left = (width - side) // 2
    top = (height - side) // 2
    image = image.crop((left, top, left + side, top + side))
    image = image.resize((AVATAR_DIMENSION, AVATAR_DIMENSION), Image.LANCZOS)

    out = io.BytesIO()
    image.save(out, format="JPEG", quality=85)
    return out.getvalue()


def store_avatar(user_id: int, image_bytes: bytes) -> str:
    """Upload processed JPEG bytes, return the new object key."""
    client = get_s3_client()
    bucket = _avatar_bucket_name()
    _ensure_bucket(client, bucket)
    key = f"avatars/{user_id}/{uuid.uuid4().hex}.jpg"
    client.put_object(
        bucket, key, io.BytesIO(image_bytes),
        length=len(image_bytes), content_type="image/jpeg",
    )
    return key


def delete_avatar(key: str) -> None:
    """Best-effort delete of a previous avatar object. Never raises."""
    try:
        client = get_s3_client()
        client.remove_object(_avatar_bucket_name(), key)
    except Exception as exc:
        logger.warning(f"Failed to delete avatar object {key!r}: {exc}")


def presigned_avatar_url(key: str) -> str | None:
    """Presigned GET URL for a stored avatar, or None on any failure."""
    try:
        client = get_s3_client()
        return client.presigned_get_object(
            _avatar_bucket_name(), key, expires=AVATAR_URL_EXPIRES
        )
    except Exception as exc:
        logger.warning(f"Failed to presign avatar URL for {key!r}: {exc}")
        return None
