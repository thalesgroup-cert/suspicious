import io
import os
import uuid
from datetime import timedelta
from unittest import skipUnless
from unittest.mock import MagicMock
from urllib.parse import urlparse

import boto3
from botocore.config import Config
from boto3.exceptions import S3UploadFailedError
from botocore.exceptions import (
    ClientError, ConnectTimeoutError, EndpointConnectionError, NoCredentialsError, ParamValidationError,
    PartialCredentialsError,
)
from botocore.stub import Stubber
from django.test import SimpleTestCase

from common.storage import base
from common.storage.base import StoreError
from common.storage.s3 import S3Store
from common.tests.storage_contract import StoreContract


def _client(endpoint="http://rustfs:9000"):
    return boto3.client(
        "s3", endpoint_url=endpoint, aws_access_key_id="ak", aws_secret_access_key="sk",
        config=Config(signature_version="s3v4", region_name="us-east-1", s3={"addressing_style": "path"}),
    )


def _client_error(code, status):
    return ClientError({"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": status}}, "Op")


def _store(client=None):
    return S3Store(endpoint="rustfs:9000", access_key="ak", secret_key="sk", client=client or _client())


class _Body:
    def __init__(self, data):
        self.data = data

    def read(self, size=None):
        if size is None:
            raise AssertionError("whole body was read")
        return self.data[:size]

    def iter_chunks(self, chunk_size=1 << 20):
        for i in range(0, len(self.data), chunk_size):
            yield self.data[i:i + chunk_size]

    def close(self):
        pass


class S3StoreTests(SimpleTestCase):
    def test_client_config_pins_path_style_sigv4_and_checksums(self):
        cfg = S3Store(endpoint="rustfs:9000", access_key="ak", secret_key="sk")._client.meta.config
        self.assertEqual(cfg.signature_version, "s3v4")
        self.assertEqual(cfg.s3["addressing_style"], "path")
        self.assertEqual(cfg.region_name, "us-east-1")
        self.assertEqual(cfg.request_checksum_calculation, "when_required")
        self.assertEqual(cfg.response_checksum_validation, "when_required")
        self.assertEqual(cfg.retries["total_max_attempts"], 3)  # max_attempts=2 retries in legacy mode
        self.assertEqual((cfg.connect_timeout, cfg.read_timeout), (5, 15))

    def test_error_mapping(self):
        from botocore.exceptions import EndpointConnectionError as E
        table = [
            (_client_error("NoSuchKey", 404), "not_found"),
            (_client_error("NoSuchBucket", 404), "not_found"),
            (_client_error("404", 404), "not_found"),
            (_client_error("AccessDenied", 403), "access_denied"),
            (_client_error("403", 403), "access_denied"),
            (_client_error("InvalidArgument", 400), "invalid"),
            (_client_error("InternalError", 500), "unavailable"),
            (_client_error("Whatever", 408), "unavailable"),
            (_client_error("Whatever", 429), "unavailable"),
            (_client_error("RequestTimeout", 400), "unavailable"),
            (_client_error("SlowDown", 503), "unavailable"),
            (_client_error("Throttling", 400), "unavailable"),
            (_client_error("ThrottlingException", 400), "unavailable"),
            (_client_error("InternalError", 0), "unavailable"),
            (E(endpoint_url="http://x"), "unavailable"),
            (ConnectTimeoutError(endpoint_url="http://x"), "unavailable"),
            (ParamValidationError(report="bad"), "invalid"),
            (NoCredentialsError(), "access_denied"),
            (PartialCredentialsError(provider="p", cred_var="v"), "access_denied"),
        ]
        for exc, code in table:
            client = MagicMock()
            client.head_object.side_effect = exc
            with self.assertRaises(StoreError, msg=repr(exc)) as ctx:
                _store(client).stat("b", "k")
            self.assertEqual(ctx.exception.code, code, repr(exc))

    def test_ensure_bucket_treats_already_codes_as_success(self):
        for code in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
            client = _client()
            with Stubber(client) as stub:
                stub.add_client_error("head_bucket", "404", http_status_code=404)
                stub.add_client_error("create_bucket", code, http_status_code=409)
                _store(client).ensure_bucket("b")
                stub.assert_no_pending_responses()

    def test_ensure_bucket_skips_create_when_present(self):
        client = _client()
        with Stubber(client) as stub:
            stub.add_response("head_bucket", {})
            _store(client).ensure_bucket("b")
            stub.assert_no_pending_responses()

    def test_open_streams_without_reading_whole_body(self):
        client = _client()
        with Stubber(client) as stub:
            stub.add_response("get_object", {"Body": _Body(b"abcdefghijkl")})
            with _store(client).open("b", "k") as stream:
                self.assertEqual(list(stream.iter_chunks(4)), [b"abcd", b"efgh", b"ijkl"])
        with Stubber(client) as stub:
            stub.add_response("get_object", {"Body": _Body(b"abcdef")})
            with _store(client).open("b", "k") as stream:
                self.assertEqual(stream.read(3), b"abc")

    def test_put_bytes_uses_put_object_with_tags_and_metadata(self):
        client = _client()
        with Stubber(client) as stub:
            stub.add_response("put_object", {}, {
                "Bucket": "b", "Key": "k", "Body": b"hi", "ContentType": "text/plain",
                "Metadata": {"a": "1"}, "Tagging": "t=v%20w",
            })
            _store(client).put("b", "k", b"hi", content_type="text/plain", metadata={"a": "1"}, tags={"t": "v w"})
            stub.assert_no_pending_responses()

    def test_put_unknown_length_uses_upload_fileobj(self):
        client = MagicMock()
        data = io.BytesIO(b"hi")
        _store(client).put("b", "k", data)
        client.upload_fileobj.assert_called_once_with(data, "b", "k", ExtraArgs={})
        client.put_object.assert_not_called()

    def test_streaming_put_unwraps_client_error(self):
        for name, status, code in (("NoSuchBucket", 404, "not_found"), ("AccessDenied", 403, "access_denied")):
            client = MagicMock()
            try:
                raise _client_error(name, status)
            except ClientError as inner:
                try:
                    raise S3UploadFailedError("upload failed") from inner
                except S3UploadFailedError as wrapped:
                    client.upload_fileobj.side_effect = wrapped
            with self.assertRaises(StoreError) as ctx:
                _store(client).put("b", "k", io.BytesIO(b"x"))
            self.assertEqual(ctx.exception.code, code)

    def test_missing_bucket_is_not_found_on_list_prefixes_and_open(self):
        calls = {
            "list_objects_v2": [lambda s: list(s.list("b")), lambda s: list(s.list_prefixes("b"))],
            "get_object": [lambda s: s.open("b", "k").__enter__()],
        }
        for op, fns in calls.items():
            for fn in fns:
                client = _client()
                with Stubber(client) as stub:
                    stub.add_client_error(op, "NoSuchBucket", http_status_code=404)
                    with self.assertRaises(StoreError) as ctx:
                        fn(_store(client))
                self.assertEqual(ctx.exception.code, "not_found")

    def test_delete_many_batches_of_1000(self):
        client = _client()
        keys = [f"k{i}" for i in range(2500)]
        with Stubber(client) as stub:
            for start, end in ((0, 1000), (1000, 2000), (2000, 2500)):
                stub.add_response("delete_objects", {}, {
                    "Bucket": "b",
                    "Delete": {"Objects": [{"Key": k} for k in keys[start:end]], "Quiet": True},
                })
            _store(client).delete_many("b", iter(keys))
            stub.assert_no_pending_responses()

    def test_delete_many_reports_per_key_errors(self):
        client = _client()
        with Stubber(client) as stub:
            stub.add_response("delete_objects", {"Errors": [{"Key": "k", "Code": "AccessDenied"}]})
            with self.assertRaises(StoreError) as ctx:
                _store(client).delete_many("b", ["k"])
        self.assertEqual(ctx.exception.code, "access_denied")

    def test_list_follows_continuation_tokens(self):
        client = _client()
        with Stubber(client) as stub:
            stub.add_response("list_objects_v2", {
                "Contents": [{"Key": "a", "Size": 1, "ETag": '"e1"'}],
                "IsTruncated": True, "NextContinuationToken": "t1",
            }, {"Bucket": "b", "Prefix": "p/"})
            stub.add_response("list_objects_v2", {
                "Contents": [{"Key": "b", "Size": 2, "ETag": '"e2"'}],
            }, {"Bucket": "b", "Prefix": "p/", "ContinuationToken": "t1"})
            infos = list(_store(client).list("b", "p/"))
        self.assertEqual([(i.name, i.size, i.etag) for i in infos], [("a", 1, "e1"), ("b", 2, "e2")])

    def test_list_prefixes_uses_delimiter(self):
        client = _client()
        with Stubber(client) as stub:
            stub.add_response("list_objects_v2", {
                "CommonPrefixes": [{"Prefix": "d/"}, {"Prefix": "e/"}],
            }, {"Bucket": "b", "Prefix": "", "Delimiter": "/"})
            self.assertEqual(list(_store(client).list_prefixes("b")), ["d/", "e/"])

    def test_list_non_recursive_yields_dirs(self):
        client = _client()
        with Stubber(client) as stub:
            stub.add_response("list_objects_v2", {
                "Contents": [{"Key": "d/a", "Size": 1}], "CommonPrefixes": [{"Prefix": "d/sub/"}],
            }, {"Bucket": "b", "Prefix": "d/", "Delimiter": "/"})
            infos = list(_store(client).list("b", "d/", recursive=False))
        self.assertEqual([(i.name, i.is_dir) for i in infos], [("d/a", False), ("d/sub/", True)])

    def test_bucket_labels_map_to_bucket_tagging(self):
        client = _client()
        with Stubber(client) as stub:
            stub.add_response("put_bucket_tagging", {}, {
                "Bucket": "b", "Tagging": {"TagSet": [{"Key": "Status", "Value": "To Do"}]},
            })
            stub.add_response("get_bucket_tagging", {"TagSet": [{"Key": "Status", "Value": "To Do"}]})
            store = _store(client)
            store.set_bucket_labels("b", {"Status": "To Do"})
            self.assertEqual(store.get_bucket_labels("b"), {"Status": "To Do"})

    def test_bucket_labels_without_tags_is_empty(self):
        client = _client()
        with Stubber(client) as stub:
            stub.add_client_error("get_bucket_tagging", "NoSuchTagSet", http_status_code=404)
            self.assertEqual(_store(client).get_bucket_labels("b"), {})

    def test_presign_uses_public_endpoint_and_never_connects(self):
        store = S3Store.from_config(
            {"endpoint": "rustfs:9000", "public_endpoint": "files.example.com:9443", "public_secure": True,
             "access_key": "ak", "secret_key": "sk"},
            presign=True,
        )
        with Stubber(store._client) as stub:
            url = store.presign_get("b", "a.eml", timedelta(minutes=5), filename="a.eml")
            put_url = store.presign_put("b", "a.eml", timedelta(minutes=5), content_type="message/rfc822")
            stub.assert_no_pending_responses()
        parsed = urlparse(url)
        self.assertEqual((parsed.scheme, parsed.netloc), ("https", "files.example.com:9443"))
        self.assertIn("X-Amz-Expires=300", url)
        self.assertIn("response-content-disposition", url)
        self.assertEqual(urlparse(put_url).netloc, "files.example.com:9443")

    def test_from_config_falls_back_to_endpoint(self):
        cfg = {"endpoint": "rustfs:9000", "access_key": "ak", "secret_key": "sk", "secure": True}
        client = S3Store.from_config(cfg, presign=True)._client
        self.assertEqual(client.meta.endpoint_url, "https://rustfs:9000")
        client = S3Store.from_config(cfg)._client
        self.assertEqual(client.meta.endpoint_url, "https://rustfs:9000")

    def test_capabilities(self):
        self.assertEqual(_store().capabilities, frozenset({
            base.OBJECT_TAGS, base.FREE_FORM_BUCKET_TAGS, base.LIFECYCLE, base.BATCH_DELETE, base.PRESIGN_PUT,
        }))

    def test_health_reports_unavailable(self):
        client = MagicMock()
        client.list_buckets.side_effect = EndpointConnectionError(endpoint_url="http://x")
        status = _store(client).health()
        self.assertFalse(status.ok)


@skipUnless(os.environ.get("STORAGE_LIVE_ENDPOINT"), "set STORAGE_LIVE_ENDPOINT to run against a real S3")
class LiveS3Contract(StoreContract, SimpleTestCase):
    bucket = f"contract-{uuid.uuid4().hex[:12]}"

    def make_store(self):
        return S3Store(
            endpoint=os.environ["STORAGE_LIVE_ENDPOINT"],
            access_key=os.environ["STORAGE_LIVE_ACCESS_KEY"],
            secret_key=os.environ["STORAGE_LIVE_SECRET_KEY"],
        )

    def tearDown(self):
        keys = [o.name for o in self.store.list(self.bucket)]
        self.store.delete_many(self.bucket, keys)
        self.store._client.delete_bucket(Bucket=self.bucket)
        super().tearDown()
