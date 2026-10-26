from __future__ import annotations

from abc import ABC, abstractmethod
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import BinaryIO, Iterable, Iterator, Protocol

CODES = ("not_found", "already_exists", "access_denied", "unavailable", "invalid")

OBJECT_TAGS = "object_tags"
FREE_FORM_BUCKET_TAGS = "free_form_bucket_tags"
LIFECYCLE = "lifecycle"
OBJECT_LOCK = "object_lock"
BATCH_DELETE = "batch_delete"
PRESIGN_PUT = "presign_put"


class StoreError(Exception):
    def __init__(self, code: str, message: str = "", *, bucket: str | None = None, key: str | None = None):
        if code not in CODES:
            raise ValueError(f"unknown store error code: {code!r}")
        super().__init__(message or code)
        self.code = code
        self.bucket = bucket
        self.key = key


@dataclass(frozen=True)
class ObjectInfo:
    name: str
    size: int = 0
    etag: str | None = None
    last_modified: datetime | None = None
    metadata: dict[str, str] = field(default_factory=dict)
    is_dir: bool = False


@dataclass(frozen=True)
class HealthStatus:
    ok: bool
    detail: str = ""


class ObjectStream(Protocol):
    def read(self, size: int = -1) -> bytes: ...
    def iter_chunks(self, chunk_size: int = 1 << 20) -> Iterator[bytes]: ...
    def close(self) -> None: ...


class ObjectStore(ABC):
    @abstractmethod
    def put(self, bucket: str, key: str, data: BinaryIO, *, length: int | None = None,
            content_type: str | None = None, metadata: dict[str, str] | None = None,
            tags: dict[str, str] | None = None) -> None: ...

    @abstractmethod
    def open(self, bucket: str, key: str) -> AbstractContextManager[ObjectStream]: ...

    @abstractmethod
    def download(self, bucket: str, key: str, path: str) -> None: ...

    @abstractmethod
    def stat(self, bucket: str, key: str) -> ObjectInfo: ...

    @abstractmethod
    def list(self, bucket: str, prefix: str = "", recursive: bool = True) -> Iterator[ObjectInfo]: ...

    @abstractmethod
    def list_prefixes(self, bucket: str, prefix: str = "") -> Iterator[str]: ...

    @abstractmethod
    def delete(self, bucket: str, key: str) -> None: ...

    @abstractmethod
    def delete_many(self, bucket: str, keys: Iterable[str]) -> None: ...

    @abstractmethod
    def bucket_exists(self, bucket: str) -> bool: ...

    @abstractmethod
    def ensure_bucket(self, bucket: str) -> None: ...

    @abstractmethod
    def list_buckets(self) -> list[str]: ...

    @abstractmethod
    def get_bucket_labels(self, bucket: str) -> dict[str, str]: ...

    @abstractmethod
    def set_bucket_labels(self, bucket: str, labels: dict[str, str]) -> None: ...

    @abstractmethod
    def presign_get(self, bucket: str, key: str, expires: timedelta, *, filename: str | None = None) -> str: ...

    @abstractmethod
    def presign_put(self, bucket: str, key: str, expires: timedelta, *, content_type: str | None = None) -> str: ...

    @property
    @abstractmethod
    def capabilities(self) -> frozenset[str]: ...

    @abstractmethod
    def health(self) -> HealthStatus: ...
