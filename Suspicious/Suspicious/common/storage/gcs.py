from __future__ import annotations

import io
import json
import logging
import re
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import timedelta
from typing import Callable

import requests
from google.api_core import exceptions as gx
from google.auth import exceptions as ax
from google.auth.credentials import Signing

from . import base
from .base import HealthStatus, ObjectInfo, ObjectStore, ObjectStream, StoreError
from .util import content_disposition

logger = logging.getLogger(__name__)

_CHUNK = 262144

_LABEL_KEY = re.compile(r"[a-z][a-z0-9_-]{0,62}")
_LABEL_VALUE = re.compile(r"[a-z0-9_-]{0,63}")
_MAX_LABELS = 64

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


def _validate_labels(bucket, labels):
    if len(labels) > _MAX_LABELS:
        raise StoreError("invalid", f"at most {_MAX_LABELS} labels, got {len(labels)}", bucket=bucket)
    for key, value in labels.items():
        if not _LABEL_KEY.fullmatch(key):
            raise StoreError("invalid", f"invalid label key: {key!r}", bucket=bucket)
        if not _LABEL_VALUE.fullmatch(value):
            raise StoreError("invalid", f"invalid value for label {key!r}", bucket=bucket)


@dataclass(frozen=True)
class Signer:
    credentials: Signing | None = None
    service_account_email: str | None = None
    token: Callable[[], str] | None = None


def _keyless(creds, email_override) -> Signer | None:
    import google.auth.transport.requests

    def token() -> str:
        if not creds.valid:
            creds.refresh(google.auth.transport.requests.Request())
        return creds.token

    try:
        if not email_override:
            token()  # a Compute credential reports "default" as its email until refreshed
    except ax.GoogleAuthError as exc:
        logger.warning("gcs: could not resolve signing identity: %s", type(exc).__name__)
        return None
    email = email_override or getattr(creds, "service_account_email", None)
    if not email or email == "default":
        logger.warning("gcs: no signing service account email resolved; set storage.gcs.signing_service_account_email")
        return None
    return Signer(service_account_email=email, token=token)


class GcsStore(ObjectStore):
    def __init__(self, *, client, signing=None, location: str | None = None, project: str | None = None):
        self._client, self._signing, self._location, self._project = client, signing, location, project

    @classmethod
    def from_config(cls, cfg: dict, *, presign: bool = False) -> "GcsStore":
        import google.auth
        from google.auth.credentials import AnonymousCredentials
        from google.cloud import storage
        from google.oauth2 import service_account

        from .registry import StorageConfigError

        mode = str(cfg.get("credentials") or "adc").strip().lower()
        project = cfg.get("project") or None
        if mode == "service_account":
            try:
                info = json.loads(cfg.get("service_account_json") or "")
                creds = service_account.Credentials.from_service_account_info(info)
            except (ValueError, TypeError, KeyError, AttributeError):
                raise StorageConfigError(
                    "storage.gcs.service_account_json is missing or not a valid service account key") from None
            signing = Signer(credentials=creds)
            project = project or info.get("project_id")
        elif mode == "anonymous":
            creds, signing = AnonymousCredentials(), None
        elif mode == "adc":
            try:
                creds, adc_project = google.auth.default()
            except ax.DefaultCredentialsError:
                raise StorageConfigError("storage.gcs.credentials is adc but no Application Default "
                                         "Credentials were found") from None
            project = project or adc_project
            signing = (Signer(credentials=creds) if isinstance(creds, Signing)
                       else _keyless(creds, cfg.get("signing_service_account_email")))
        else:
            raise StorageConfigError(
                f"storage.gcs.credentials must be adc, service_account or anonymous, got {mode!r}")
        options = {"api_endpoint": cfg["api_endpoint"]} if cfg.get("api_endpoint") else None
        client = storage.Client(project=project, credentials=creds, client_options=options)
        return cls(client=client, signing=signing, location=cfg.get("location") or None, project=project)

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
            blob = self._client.bucket(bucket).blob(key)
            blob.reload()  # BlobReader is lazy; fail here, not on first read
            reader = blob.open("rb", chunk_size=_CHUNK)
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

    def bucket_exists(self, bucket):
        with _errors(bucket):
            return self._client.bucket(bucket).exists()

    def ensure_bucket(self, bucket):
        if self.bucket_exists(bucket):
            return
        try:
            with _errors(bucket):
                self._client.create_bucket(bucket, location=self._location, project=self._project)
        except StoreError as exc:
            if exc.code != "already_exists" or not self.bucket_exists(bucket):
                raise

    def list_buckets(self):
        with _errors():
            return [b.name for b in self._client.list_buckets(project=self._project)]

    def get_bucket_labels(self, bucket):
        with _errors(bucket):
            b = self._client.bucket(bucket)
            b.reload()
            return dict(b.labels or {})

    def set_bucket_labels(self, bucket, labels):
        _validate_labels(bucket, labels)
        with _errors(bucket):
            b = self._client.bucket(bucket)
            b.reload()  # the labels setter derives removals from the loaded set; patch() only merges
            b.labels = dict(labels)
            b.patch()

    def _signed_url(self, blob, **kwargs) -> str:
        s = self._signing
        keyed = s is not None and isinstance(s.credentials, Signing)
        if not keyed and (s is None or not (s.service_account_email and s.token)):
            raise StoreError("invalid", "signing is not configured: provide service account key credentials "
                             "or a service account email with a token source "
                             "(storage.gcs.signing_service_account_email)", bucket=blob.bucket.name, key=blob.name)
        with _errors(blob.bucket.name, blob.name):
            if keyed:
                return blob.generate_signed_url(version="v4", credentials=s.credentials, **kwargs)
            return blob.generate_signed_url(version="v4", service_account_email=s.service_account_email,
                                            access_token=s.token(), **kwargs)

    def presign_get(self, bucket, key, expires: timedelta, *, filename=None):
        extra = {"response_disposition": content_disposition(filename)} if filename else {}
        return self._signed_url(self._client.bucket(bucket).blob(key), method="GET", expiration=expires, **extra)

    def presign_put(self, bucket, key, expires: timedelta, *, content_type=None):
        extra = {"content_type": content_type} if content_type else {}
        return self._signed_url(self._client.bucket(bucket).blob(key), method="PUT", expiration=expires, **extra)

    @property
    def capabilities(self):
        caps = {base.OBJECT_TAGS, base.LIFECYCLE}
        if self._signing is not None:
            caps.add(base.PRESIGN_PUT)
        return frozenset(caps)

    def health(self):
        try:
            self.list_buckets()
        except StoreError as exc:
            return HealthStatus(ok=False, detail=f"{exc.code}: {exc}")
        return HealthStatus(ok=True)
