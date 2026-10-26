import hashlib
from contextlib import closing
from datetime import datetime, timezone

from .base import HealthStatus, ObjectInfo, ObjectStore, StoreError


class _Stream:
    def __init__(self, data: bytes):
        self._data, self._pos = data, 0

    def read(self, size: int = -1) -> bytes:
        end = len(self._data) if size < 0 else self._pos + size
        chunk, self._pos = self._data[self._pos:end], min(end, len(self._data))
        return chunk

    def iter_chunks(self, chunk_size: int = 1 << 20):
        while chunk := self.read(chunk_size):
            yield chunk

    def close(self) -> None:
        pass


class FakeObjectStore(ObjectStore):
    """In-memory store used by tests; honours the whole interface."""

    def __init__(self, capabilities=frozenset()):
        self._caps = frozenset(capabilities)
        self._buckets: dict[str, dict[str, ObjectInfo]] = {}
        self._data: dict[tuple[str, str], bytes] = {}
        self._labels: dict[str, dict[str, str]] = {}

    def _bucket(self, bucket):
        if bucket not in self._buckets:
            raise StoreError("not_found", "no such bucket", bucket=bucket)
        return self._buckets[bucket]

    def _blob(self, bucket, key):
        self._bucket(bucket)
        if (bucket, key) not in self._data:
            raise StoreError("not_found", "no such key", bucket=bucket, key=key)
        return self._data[(bucket, key)]

    def put(self, bucket, key, data, *, length=None, content_type=None, metadata=None, tags=None):
        objects = self._bucket(bucket)
        body = data.read() if length is None else data.read(length)
        self._data[(bucket, key)] = body
        objects[key] = ObjectInfo(
            name=key, size=len(body), etag=hashlib.md5(body).hexdigest(),
            last_modified=datetime.now(timezone.utc), metadata=dict(metadata or {}),
        )

    def open(self, bucket, key):
        stream = _Stream(self._blob(bucket, key))
        return closing(stream)

    def download(self, bucket, key, path):
        with open(path, "wb") as fh:
            fh.write(self._blob(bucket, key))

    def stat(self, bucket, key):
        self._blob(bucket, key)
        return self._buckets[bucket][key]

    def list(self, bucket, prefix="", recursive=True):
        seen = set()
        for key in sorted(self._bucket(bucket)):
            if not key.startswith(prefix):
                continue
            rest = key[len(prefix):]
            if recursive or "/" not in rest:
                yield self._buckets[bucket][key]
            else:
                folder = prefix + rest.split("/", 1)[0] + "/"
                if folder not in seen:
                    seen.add(folder)
                    yield ObjectInfo(name=folder, is_dir=True)

    def list_prefixes(self, bucket, prefix=""):
        return (o.name for o in self.list(bucket, prefix, recursive=False) if o.is_dir)

    def delete(self, bucket, key):
        self._bucket(bucket).pop(key, None)
        self._data.pop((bucket, key), None)

    def delete_many(self, bucket, keys):
        for key in keys:
            self.delete(bucket, key)

    def bucket_exists(self, bucket):
        return bucket in self._buckets

    def ensure_bucket(self, bucket):
        self._buckets.setdefault(bucket, {})

    def list_buckets(self):
        return sorted(self._buckets)

    def get_bucket_labels(self, bucket):
        self._bucket(bucket)
        return dict(self._labels.get(bucket, {}))

    def set_bucket_labels(self, bucket, labels):
        self._bucket(bucket)
        self._labels[bucket] = dict(labels)

    def presign_get(self, bucket, key, expires, *, filename=None):
        return f"fake://{bucket}/{key}?expires={int(expires.total_seconds())}"

    def presign_put(self, bucket, key, expires, *, content_type=None):
        return f"fake://{bucket}/{key}?expires={int(expires.total_seconds())}"

    @property
    def capabilities(self):
        return self._caps

    def health(self):
        return HealthStatus(ok=True)
