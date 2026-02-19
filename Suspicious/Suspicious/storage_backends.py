# suspicious/storage_backends.py
from __future__ import annotations

from django.conf import settings
from django.core.files.storage import FileSystemStorage, Storage

try:
    from minio_storage.storage import MinioMediaStorage
except Exception:  # pragma: no cover
    MinioMediaStorage = None  # type: ignore


def _bool(val: str | bool | None, default: bool = False) -> bool:
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    return val.strip().lower() in {"1", "true", "yes", "on"}


class DualStorage(Storage):
    """
    Primary = MinIO, Secondary = local filesystem.
    - Save: always to primary; optionally also to secondary (dual write).
    - Open/exists: prefer primary, fallback to secondary for backward compatibility.
    """

    def __init__(self, *args, **kwargs):
        if MinioMediaStorage is None:
            raise RuntimeError("minio_storage is required for DualStorage")

        self.primary = MinioMediaStorage()
        self.secondary = FileSystemStorage(location=settings.MEDIA_ROOT, base_url=settings.MEDIA_URL)

        self.dual_write = _bool(getattr(settings, "SUSPICIOUS_STORAGE_DUAL_WRITE", False), default=False)

    def _open(self, name, mode="rb"):
        if self.primary.exists(name):
            return self.primary.open(name, mode)
        return self.secondary.open(name, mode)

    def _save(self, name, content):
        saved = self.primary.save(name, content)
        if self.dual_write:
            # best effort: store also locally (useful during transition)
            try:
                content.seek(0)
                self.secondary.save(saved, content)
            except Exception:
                pass
        return saved

    def delete(self, name):
        # best effort delete both
        if self.primary.exists(name):
            self.primary.delete(name)
        if self.secondary.exists(name):
            self.secondary.delete(name)

    def exists(self, name):
        return self.primary.exists(name) or self.secondary.exists(name)

    def url(self, name):
        if self.primary.exists(name):
            return self.primary.url(name)
        return self.secondary.url(name)
