from __future__ import annotations

from contextlib import contextmanager
from datetime import timedelta
from urllib.parse import quote, urlencode

import boto3
from boto3.exceptions import Boto3Error
from botocore.config import Config
from botocore.exceptions import (
    BotoCoreError, ClientError, NoCredentialsError, ParamValidationError, PartialCredentialsError,
)

from . import base
from .base import HealthStatus, ObjectInfo, ObjectStore, ObjectStream, StoreError

_DEFAULT_REGION = "us-east-1"
_DELETE_BATCH = 1000

_NOT_FOUND = {"NoSuchKey", "NoSuchBucket", "NotFound", "404"}
_DENIED = {"AccessDenied", "Forbidden", "403", "AllAccessDisabled", "InvalidAccessKeyId", "SignatureDoesNotMatch"}
_ALREADY = {"BucketAlreadyOwnedByYou", "BucketAlreadyExists"}


def _map(exc: Exception, bucket=None, key=None) -> StoreError:
    code, message = "unavailable", str(exc)
    cause = exc.__cause__ or exc.__context__
    if not isinstance(exc, ClientError) and isinstance(cause, ClientError):
        exc = cause
    if isinstance(exc, ParamValidationError):
        code = "invalid"
    elif isinstance(exc, (NoCredentialsError, PartialCredentialsError)):
        code = "access_denied"
    elif isinstance(exc, ClientError):
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 0)
        name = str(err.get("Code", ""))
        if name in _NOT_FOUND:
            code = "not_found"
        elif name in _DENIED:
            code = "access_denied"
        elif name in _ALREADY:
            code = "already_exists"
        elif status >= 500:
            code = "unavailable"
        else:
            code = "invalid"
    return StoreError(code, message, bucket=bucket, key=key)


@contextmanager
def _errors(bucket=None, key=None):
    try:
        yield
    except StoreError:
        raise
    except (ClientError, BotoCoreError, Boto3Error) as exc:
        raise _map(exc, bucket, key) from exc


class _Stream:
    def __init__(self, body, bucket, key):
        self._body, self._bucket, self._key = body, bucket, key

    def read(self, size: int = -1) -> bytes:
        with _errors(self._bucket, self._key):
            return self._body.read(None if size < 0 else size)

    def iter_chunks(self, chunk_size: int = 1 << 20):
        with _errors(self._bucket, self._key):
            yield from self._body.iter_chunks(chunk_size)

    def close(self) -> None:
        self._body.close()


def _info(key, item) -> ObjectInfo:
    return ObjectInfo(
        name=key, size=item.get("Size", item.get("ContentLength", 0)),
        etag=(item.get("ETag") or "").strip('"') or None,
        last_modified=item.get("LastModified"), metadata=dict(item.get("Metadata") or {}),
    )


class S3Store(ObjectStore):
    def __init__(self, *, endpoint: str, access_key: str, secret_key: str, secure: bool = False,
                 region: str = _DEFAULT_REGION, client=None):
        self._region = region
        self._client = client or boto3.client(
            "s3",
            endpoint_url=f"{'https' if secure else 'http'}://{endpoint}",
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            config=Config(
                signature_version="s3v4",
                region_name=region,
                s3={"addressing_style": "path"},
                retries={"max_attempts": 2},
                connect_timeout=5,
                read_timeout=15,
                request_checksum_calculation="when_required",
                response_checksum_validation="when_required",
            ),
        )

    @classmethod
    def from_config(cls, cfg: dict, *, presign: bool = False) -> "S3Store":
        if presign:
            endpoint = cfg.get("public_endpoint") or cfg["endpoint"]
            secure = cfg.get("public_secure", cfg.get("secure", False))
        else:
            endpoint, secure = cfg["endpoint"], cfg.get("secure", False)
        return cls(endpoint=endpoint, access_key=cfg["access_key"], secret_key=cfg["secret_key"],
                   secure=secure, region=cfg.get("region", _DEFAULT_REGION))

    def put(self, bucket, key, data, *, length=None, content_type=None, metadata=None, tags=None):
        extra = {}
        if content_type:
            extra["ContentType"] = content_type
        if metadata:
            extra["Metadata"] = metadata
        if tags:
            extra["Tagging"] = urlencode(tags)
        with _errors(bucket, key):
            if isinstance(data, (bytes, bytearray)) or length is not None:
                args = {"Bucket": bucket, "Key": key, "Body": data, **extra}
                if length is not None:
                    args["ContentLength"] = length
                self._client.put_object(**args)
            else:
                self._client.upload_fileobj(data, bucket, key, ExtraArgs=extra)

    @contextmanager
    def open(self, bucket, key):
        with _errors(bucket, key):
            body = self._client.get_object(Bucket=bucket, Key=key)["Body"]
        stream: ObjectStream = _Stream(body, bucket, key)
        try:
            yield stream
        finally:
            stream.close()

    def download(self, bucket, key, path):
        with _errors(bucket, key):
            self._client.download_file(bucket, key, path)

    def stat(self, bucket, key):
        with _errors(bucket, key):
            return _info(key, self._client.head_object(Bucket=bucket, Key=key))

    def _pages(self, bucket, prefix, delimiter):
        args = {"Bucket": bucket, "Prefix": prefix}
        if delimiter:
            args["Delimiter"] = delimiter
        with _errors(bucket):
            yield from self._client.get_paginator("list_objects_v2").paginate(**args)

    def list(self, bucket, prefix="", recursive=True):
        for page in self._pages(bucket, prefix, None if recursive else "/"):
            for item in page.get("Contents", []):
                yield _info(item["Key"], item)
            for cp in page.get("CommonPrefixes", []):
                yield ObjectInfo(name=cp["Prefix"], is_dir=True)

    def list_prefixes(self, bucket, prefix=""):
        for page in self._pages(bucket, prefix, "/"):
            for cp in page.get("CommonPrefixes", []):
                yield cp["Prefix"]

    def delete(self, bucket, key):
        with _errors(bucket, key):
            self._client.delete_object(Bucket=bucket, Key=key)

    def delete_many(self, bucket, keys):
        batch = []
        for key in keys:
            batch.append({"Key": key})
            if len(batch) == _DELETE_BATCH:
                self._delete_batch(bucket, batch)
                batch = []
        if batch:
            self._delete_batch(bucket, batch)

    def _delete_batch(self, bucket, objects):
        with _errors(bucket):
            resp = self._client.delete_objects(Bucket=bucket, Delete={"Objects": objects, "Quiet": True})
        errors = resp.get("Errors")
        if errors:
            first = errors[0]
            raise _map(ClientError({"Error": {"Code": first.get("Code", "")}}, "DeleteObjects"),
                       bucket, first.get("Key"))

    def bucket_exists(self, bucket):
        try:
            with _errors(bucket):
                self._client.head_bucket(Bucket=bucket)
        except StoreError as exc:
            if exc.code == "not_found":
                return False
            raise
        return True

    def ensure_bucket(self, bucket):
        if self.bucket_exists(bucket):
            return
        args = {"Bucket": bucket}
        if self._region != _DEFAULT_REGION:
            args["CreateBucketConfiguration"] = {"LocationConstraint": self._region}
        try:
            with _errors(bucket):
                self._client.create_bucket(**args)
        except StoreError as exc:
            if exc.code != "already_exists":
                raise

    def list_buckets(self):
        with _errors():
            return [b["Name"] for b in self._client.list_buckets().get("Buckets", [])]

    def get_bucket_labels(self, bucket):
        with _errors(bucket):
            try:
                tags = self._client.get_bucket_tagging(Bucket=bucket)["TagSet"]
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "NoSuchTagSet":
                    return {}
                raise
        return {t["Key"]: t["Value"] for t in tags}

    def set_bucket_labels(self, bucket, labels):
        with _errors(bucket):
            if labels:
                tag_set = [{"Key": k, "Value": v} for k, v in labels.items()]
                self._client.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": tag_set})
            else:
                self._client.delete_bucket_tagging(Bucket=bucket)

    def presign_get(self, bucket, key, expires: timedelta, *, filename=None):
        params = {"Bucket": bucket, "Key": key}
        if filename:
            params["ResponseContentDisposition"] = f"attachment; filename*=UTF-8''{quote(filename)}"
        return self._presign("get_object", params, expires)

    def presign_put(self, bucket, key, expires: timedelta, *, content_type=None):
        params = {"Bucket": bucket, "Key": key}
        if content_type:
            params["ContentType"] = content_type
        return self._presign("put_object", params, expires)

    def _presign(self, op, params, expires):
        with _errors(params["Bucket"], params["Key"]):
            return self._client.generate_presigned_url(op, Params=params, ExpiresIn=int(expires.total_seconds()))

    @property
    def capabilities(self):
        return frozenset({base.OBJECT_TAGS, base.FREE_FORM_BUCKET_TAGS, base.LIFECYCLE,
                          base.BATCH_DELETE, base.PRESIGN_PUT})

    def health(self):
        try:
            self.list_buckets()
        except StoreError as exc:
            return HealthStatus(ok=False, detail=f"{exc.code}: {exc}")
        return HealthStatus(ok=True)
