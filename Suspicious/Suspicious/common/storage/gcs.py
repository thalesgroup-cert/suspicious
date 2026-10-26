from __future__ import annotations

import io
from contextlib import contextmanager

import requests
from google.api_core import exceptions as gx
from google.auth import exceptions as ax

from .base import ObjectInfo, ObjectStore, ObjectStream, StoreError

_CHUNK = 262144

_BY_TYPE = (
    (gx.NotFound, "not_found"),
    (gx.Conflict, "already_exists"),
    ((gx.Forbidden, gx.Unauthorized, ax.DefaultCredentialsError, ax.RefreshError), "access_denied"),
    ((gx.BadRequest, ValueError), "invalid"),
    ((gx.TooManyRequests, gx.ServiceUnavailable, gx.InternalServerError, gx.GatewayTimeout,
      gx.DeadlineExceeded, gx.RetryError, requests.ConnectionError, requests.Timeout,
      ax.TransportError), "unavailable"),
)


def _map(exc: Exception, bucket=None, key=None) -> StoreError:
    code = "unavailable"
    for types, mapped in _BY_TYPE:
        if isinstance(exc, types):
            code = mapped
            break
    else:
        status = getattr(exc, "code", None) if isinstance(exc, gx.GoogleAPICallError) else None
        if isinstance(status, int) and 400 <= status < 500 and status != 408 and status != 429:
            code = "invalid"
    return StoreError(code, str(exc), bucket=bucket, key=key)


@contextmanager
def _errors(bucket=None, key=None):
    try:
        yield
    except StoreError:
        raise
    except Exception as exc:
        raise _map(exc, bucket, key) from exc


class _Stream:
    def __init__(self, reader, bucket, key):
        self._reader, self._bucket, self._key = reader, bucket, key

    def read(self, size: int = -1) -> bytes:
        with _errors(self._bucket, self._key):
            return self._reader.read(size)

    def iter_chunks(self, chunk_size: int = 1 << 20):
        with _errors(self._bucket, self._key):
            while chunk := self._reader.read(chunk_size):
                yield chunk

    def close(self) -> None:
        self._reader.close()


def _info(blob) -> ObjectInfo:
    return ObjectInfo(name=blob.name, size=blob.size or 0, etag=blob.etag,
                      last_modified=blob.updated, metadata=dict(blob.metadata or {}))


class GcsStore(ObjectStore):
    def __init__(self, *, client, signing=None, location: str | None = None, project: str | None = None):
        self._client, self._signing, self._location, self._project = client, signing, location, project

    def put(self, bucket, key, data, *, length=None, content_type=None, metadata=None, tags=None):
        custom = {**(metadata or {}), **(tags or {})}
        if len(custom) != len(metadata or {}) + len(tags or {}):
            raise StoreError("invalid", "metadata and tags share a key", bucket=bucket, key=key)
        if isinstance(data, (bytes, bytearray, memoryview)):
            data = io.BytesIO(data)
        kwargs = {}
        if length is not None:
            kwargs["size"] = length
        if content_type:
            kwargs["content_type"] = content_type
        with _errors(bucket, key):
            blob = self._client.bucket(bucket).blob(key)
            if custom:
                blob.metadata = custom
            blob.upload_from_file(data, **kwargs)

    @contextmanager
    def open(self, bucket, key):
        with _errors(bucket, key):
            reader = self._client.bucket(bucket).blob(key).open("rb", chunk_size=_CHUNK)
        stream: ObjectStream = _Stream(reader, bucket, key)
        try:
            yield stream
        finally:
            stream.close()

    def download(self, bucket, key, path):
        with _errors(bucket, key):
            self._client.bucket(bucket).blob(key).download_to_filename(path)

    def stat(self, bucket, key):
        with _errors(bucket, key):
            blob = self._client.bucket(bucket).get_blob(key)
        if blob is None:
            raise StoreError("not_found", f"no such object: {key}", bucket=bucket, key=key)
        return _info(blob)

    def _pages(self, bucket, prefix, delimiter):
        with _errors(bucket):
            yield from self._client.list_blobs(bucket, prefix=prefix, delimiter=delimiter).pages

    def list(self, bucket, prefix="", recursive=True):
        for page in self._pages(bucket, prefix, None if recursive else "/"):
            for blob in page:
                yield _info(blob)
            if not recursive:
                for p in sorted(page.prefixes):
                    yield ObjectInfo(name=p, is_dir=True)

    def list_prefixes(self, bucket, prefix=""):
        for page in self._pages(bucket, prefix, "/"):
            yield from sorted(page.prefixes)

    def delete(self, bucket, key):
        try:
            with _errors(bucket, key):
                self._client.bucket(bucket).blob(key).delete()
        except StoreError as exc:
            if exc.code != "not_found":
                raise

    def delete_many(self, bucket, keys):
        with _errors(bucket):
            b = self._client.bucket(bucket)
            b.delete_blobs([b.blob(k) for k in keys], on_error=lambda blob: None)
