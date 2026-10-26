"""Custom Django storage backends backed by the project's ObjectStore.

Wired in settings via STORAGES["default"] (Django 5.1+ replaced the old
DEFAULT_FILE_STORAGE setting):

    s3    -> MinioMediaStorage  (name kept; works with any ObjectStore provider)
    dual  -> DualStorage   (primary=object store, secondary=local FS)
    local -> FileSystemStorage
"""
from __future__ import annotations

import io
import posixpath
from urllib.parse import urljoin

from django.conf import settings
from django.core.files.base import ContentFile
from django.core.files.storage import FileSystemStorage, Storage
from django.utils.deconstruct import deconstructible

from common.storage import get_store


def _to_bool(val, default: bool = False) -> bool:
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    return str(val).strip().lower() in {"1", "true", "yes", "on"}


@deconstructible
class MinioMediaStorage(Storage):
    """Django Storage that persists objects in an object-store bucket.

    The store is resolved lazily from get_store() on first use, so
    instantiation is cheap and import-safe. A store may be injected
    (tests) as `client`.
    """

    def __init__(self, *, client=None, bucket: str | None = None):
        self._client = client
        self._bucket = bucket or getattr(
            settings, "MINIO_STORAGE_MEDIA_BUCKET_NAME", "suspicious-media"
        )
        self._auto_create = _to_bool(
            getattr(settings, "MINIO_STORAGE_AUTO_CREATE_MEDIA_BUCKET", True), True
        )

    @property
    def client(self):
        if self._client is None:
            self._client = get_store()
            if self._auto_create:
                self._client.ensure_bucket(self._bucket)
        return self._client

    # -- Storage API ----------------------------------------------------

    def _save(self, name, content):
        data = content.read()
        if isinstance(data, str):
            data = data.encode("utf-8")
        self.client.put(
            self._bucket,
            name,
            io.BytesIO(data),
            length=len(data),
            content_type=getattr(content, "content_type", None)
            or "application/octet-stream",
        )
        return name

    def _open(self, name, mode="rb"):
        with self.client.open(self._bucket, name) as stream:
            data = stream.read()
        return ContentFile(data, name=name)

    def exists(self, name):
        try:
            self.client.stat(self._bucket, name)
            return True
        except Exception:
            return False

    def delete(self, name):
        try:
            self.client.delete(self._bucket, name)
        except Exception:
            pass

    def size(self, name):
        return self.client.stat(self._bucket, name).size

    def url(self, name):
        base = settings.MEDIA_URL if settings.MEDIA_URL.endswith("/") else settings.MEDIA_URL + "/"
        return urljoin(base, str(name).lstrip("/"))

    def listdir(self, path):
        prefix = path.rstrip("/") + "/" if path else ""
        dirs: set[str] = set()
        files: list[str] = []
        for obj in self.client.list(self._bucket, prefix, False):
            name = obj.name
            rel = name[len(prefix):]
            if not rel:
                continue
            if rel.endswith("/"):
                dirs.add(rel.rstrip("/"))
            elif "/" in rel:
                dirs.add(rel.split("/", 1)[0])
            else:
                files.append(rel)
        return sorted(dirs), files


@deconstructible
class DualStorage(Storage):
    """Primary = object store, secondary = local filesystem.

    Save always writes to the object store; with dual-write enabled it best-effort
    mirrors to local too (useful during a local->object-store transition).
    Open/exists prefer the object store and fall back to local for legacy blobs.
    """

    def __init__(self, *, primary=None, secondary=None, dual_write=None):
        self.primary = primary or MinioMediaStorage()
        self.secondary = secondary or FileSystemStorage(
            location=settings.MEDIA_ROOT, base_url=settings.MEDIA_URL
        )
        if dual_write is None:
            dual_write = _to_bool(getattr(settings, "SUSPICIOUS_STORAGE_DUAL_WRITE", False))
        self.dual_write = dual_write

    def _save(self, name, content):
        saved = self.primary._save(name, content)
        if self.dual_write:
            try:
                content.seek(0)
                self.secondary._save(saved, content)
            except Exception:
                pass
        return saved

    def _open(self, name, mode="rb"):
        if self.primary.exists(name):
            return self.primary.open(name, mode)
        return self.secondary.open(name, mode)

    def exists(self, name):
        return self.primary.exists(name) or self.secondary.exists(name)

    def delete(self, name):
        if self.primary.exists(name):
            self.primary.delete(name)
        if self.secondary.exists(name):
            self.secondary.delete(name)

    def size(self, name):
        if self.primary.exists(name):
            return self.primary.size(name)
        return self.secondary.size(name)

    def url(self, name):
        if self.primary.exists(name):
            return self.primary.url(name)
        return self.secondary.url(name)

    def get_available_name(self, name, max_length=None):
        return posixpath.normpath(name).lstrip("/")
