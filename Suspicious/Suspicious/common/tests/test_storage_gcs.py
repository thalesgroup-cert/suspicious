import io
import tempfile
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlsplit

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.test import SimpleTestCase
from google.api_core import exceptions as gx
from google.auth import credentials as gcreds
from google.auth import exceptions as ax
from google.cloud import storage
from google.oauth2 import service_account

from common.storage import base, gcs
from common.storage.base import ObjectStore, StoreError
from common.storage.gcs import GcsStore, Signer

NOT_FOUND = gx.NotFound("missing")


class _Reader:
    def __init__(self, data, error=None):
        self.data, self.error, self.sizes, self.closed = io.BytesIO(data), error, [], False

    def read(self, size=-1):
        if self.error:
            raise self.error
        self.sizes.append(size)
        return self.data.read(size)

    def close(self):
        self.closed = True


class _Blob:
    def __init__(self, name, *, data=b"", error=None, size=0, etag=None, updated=None, metadata=None):
        self.name, self.error, self.metadata = name, error, metadata
        self.size, self.etag, self.updated = size, etag, updated
        self.reader = _Reader(data, error)
        self.calls = []

    def upload_from_file(self, fileobj, **kwargs):
        self.calls.append(("upload", fileobj.read(), kwargs, self.metadata))

    def open(self, mode, **kwargs):
        self.calls.append(("open", mode, kwargs))
        return self.reader

    def download_to_filename(self, path):
        if self.error:
            raise self.error
        with open(path, "wb") as fh:
            fh.write(self.reader.data.getvalue())

    def delete(self):
        self.calls.append(("delete",))
        if self.error:
            raise self.error


class _Page(list):
    prefixes = ()


class _Bucket:
    def __init__(self, client, name):
        self.client, self.name = client, name
        self._labels, self._removals = {}, set()  # real buckets load labels only on reload()

    @property
    def labels(self):
        return self._labels

    @labels.setter
    def labels(self, mapping):
        self._removals |= set(self._labels) - set(mapping)
        self._labels = dict(mapping)

    def exists(self):
        if self.client.exists_error:
            raise self.client.exists_error
        return self.name in self.client.buckets

    def reload(self):
        self._labels, self._removals = dict(self.client.labels), set()

    def patch(self):
        """Server-side merge, as in the real library: only removals tracked on this
        object delete keys."""
        self.client.patched.append(dict(self._labels))
        merged = {**self.client.labels, **self._labels}
        for key in self._removals:
            merged.pop(key, None)
        self.client.labels = merged

    def blob(self, key):
        return self.client.blobs.setdefault(key, _Blob(key))

    def get_blob(self, key):
        return self.client.blobs.get(key)

    def delete_blobs(self, blobs, on_error=None):
        self.client.deleted = [b.name for b in blobs]
        for b in blobs:
            if isinstance(b.error, gx.NotFound):
                on_error(b)
            elif b.error:
                raise b.error


class _Iterator:
    def __init__(self, pages, error=None):
        self._pages, self._error = pages, error

    @property
    def pages(self):
        if self._error:
            raise self._error
        yield from self._pages


class _Client:
    def __init__(self):
        self.blobs, self.list_calls, self.pages, self.list_error, self.deleted = {}, [], [], None, None
        self.buckets, self.exists_error, self.create_error, self.created = set(), None, None, []
        self.labels, self.patched, self.listed, self.list_buckets_error = {}, [], [], None

    def create_bucket(self, name, **kwargs):
        self.created.append((name, kwargs))
        if self.create_error:
            raise self.create_error
        self.buckets.add(name)

    def list_buckets(self, **kwargs):
        self.listed.append(kwargs)
        if self.list_buckets_error:
            raise self.list_buckets_error
        return [type("B", (), {"name": n}) for n in sorted(self.buckets)]

    def bucket(self, name):
        return _Bucket(self, name)

    def list_blobs(self, bucket, **kwargs):
        self.list_calls.append((bucket, kwargs))
        return _Iterator(self.pages, self.list_error)


def _store(client=None):
    return GcsStore(client=client or _Client())


class GcsStoreTests(SimpleTestCase):
    def test_error_mapping(self):
        table = [
            (gx.NotFound("x"), "not_found"),
            (gx.Conflict("x"), "already_exists"),
            (gx.Forbidden("x"), "access_denied"),
            (gx.Unauthorized("x"), "access_denied"),
            (ax.DefaultCredentialsError("x"), "access_denied"),
            (ax.RefreshError("x"), "access_denied"),
            (gx.BadRequest("x"), "invalid"),
            (ValueError("x"), "invalid"),
            (gx.TooManyRequests("x"), "unavailable"),
            (gx.ServiceUnavailable("x"), "unavailable"),
            (gx.InternalServerError("x"), "unavailable"),
            (gx.GatewayTimeout("x"), "unavailable"),
            (gx.DeadlineExceeded("x"), "unavailable"),
            (gx.RetryError("x", None), "unavailable"),
            (requests.ConnectionError("x"), "unavailable"),
            (requests.Timeout("x"), "unavailable"),
            (ax.TransportError("x"), "unavailable"),
            (gx.MethodNotImplemented("x"), "unavailable"),
            (gx.GoogleAPICallError("x"), "unavailable"),
            (gx.PreconditionFailed("x"), "invalid"),
            (gx.RequestRangeNotSatisfiable("x"), "invalid"),
            (RuntimeError("x"), "unavailable"),
        ]
        for exc, code in table:
            with self.subTest(exc=type(exc).__name__):
                err = gcs._map(exc, "b", "k")
                self.assertEqual((err.code, err.bucket, err.key), (code, "b", "k"))

    def test_error_mapping_by_status_code(self):
        class Odd(gx.GoogleAPICallError):
            pass

        for status, code in [(408, "unavailable"), (418, "invalid"), (502, "unavailable")]:
            exc = Odd("x")
            exc.code = status
            self.assertEqual(gcs._map(exc).code, code)

    def test_errors_passes_store_error_through_and_hides_nothing_else(self):
        original = StoreError("invalid", "x")
        with self.assertRaises(StoreError) as ctx, gcs._errors("b"):
            raise original
        self.assertIs(ctx.exception, original)
        with self.assertRaises(StoreError) as ctx, gcs._errors("b", "k"):
            raise gx.Forbidden("nope")
        self.assertEqual(ctx.exception.code, "access_denied")

    def test_put_rejects_duplicate_metadata_and_tags_keys(self):
        with self.assertRaises(StoreError) as ctx:
            _store().put("b", "k", b"x", metadata={"a": "1"}, tags={"a": "2"})
        self.assertEqual(ctx.exception.code, "invalid")

    def test_put_passes_size_content_type_and_metadata(self):
        client = _Client()
        _store(client).put("b", "k", io.BytesIO(b"hello"), length=5, content_type="text/plain",
                           metadata={"m": "1"}, tags={"t": "2"})
        op, body, kwargs, metadata = client.blobs["k"].calls[0]
        self.assertEqual((op, body), ("upload", b"hello"))
        self.assertEqual(kwargs, {"size": 5, "content_type": "text/plain"})
        self.assertEqual(metadata, {"m": "1", "t": "2"})

    def test_put_bytes_without_length_or_metadata(self):
        client = _Client()
        _store(client).put("b", "k", b"abc")
        _, body, kwargs, metadata = client.blobs["k"].calls[0]
        self.assertEqual(body, b"abc")
        self.assertNotIn("size", kwargs)
        self.assertIsNone(metadata)

    def test_put_maps_errors(self):
        client = _Client()
        client.blobs["k"] = _Blob("k")
        client.blobs["k"].upload_from_file = lambda *a, **kw: (_ for _ in ()).throw(gx.Forbidden("no"))
        with self.assertRaises(StoreError) as ctx:
            _store(client).put("b", "k", b"x")
        self.assertEqual(ctx.exception.code, "access_denied")

    def test_open_streams_in_chunks_and_maps_not_found(self):
        client = _Client()
        blob = client.blobs["k"] = _Blob("k", data=b"abcdefg")
        with _store(client).open("b", "k") as stream:
            self.assertEqual(blob.calls[0], ("open", "rb", {"chunk_size": 262144}))
            self.assertEqual(stream.read(2), b"ab")
            self.assertEqual(list(stream.iter_chunks(3)), [b"cde", b"fg"])
        self.assertTrue(blob.reader.closed)

        client.blobs["gone"] = _Blob("gone", error=NOT_FOUND)
        with self.assertRaises(StoreError) as ctx, _store(client).open("b", "gone") as stream:
            stream.read(1)
        self.assertEqual((ctx.exception.code, ctx.exception.key), ("not_found", "gone"))

    def test_download_writes_file_and_maps_errors(self):
        client = _Client()
        client.blobs["k"] = _Blob("k", data=b"payload")
        client.blobs["gone"] = _Blob("gone", error=NOT_FOUND)
        with tempfile.NamedTemporaryFile() as tmp:
            _store(client).download("b", "k", tmp.name)
            self.assertEqual(open(tmp.name, "rb").read(), b"payload")
            with self.assertRaises(StoreError) as ctx:
                _store(client).download("b", "gone", tmp.name)
        self.assertEqual(ctx.exception.code, "not_found")

    def test_stat_returns_info(self):
        client = _Client()
        when = datetime(2026, 1, 2, tzinfo=timezone.utc)
        client.blobs["k"] = _Blob("k", size=7, etag="abc=", updated=when, metadata={"m": "1"})
        info = _store(client).stat("b", "k")
        self.assertEqual((info.name, info.size, info.etag, info.last_modified, info.metadata),
                         ("k", 7, "abc=", when, {"m": "1"}))

    def test_stat_missing_is_not_found(self):
        with self.assertRaises(StoreError) as ctx:
            _store().stat("b", "nope")
        self.assertEqual((ctx.exception.code, ctx.exception.bucket, ctx.exception.key), ("not_found", "b", "nope"))

    def test_list_recursive_and_delimiter(self):
        client = _Client()
        page = _Page([_Blob("p/a", size=1, etag="e"), _Blob("p/b", size=2)])
        page.prefixes = {"p/sub/"}
        client.pages = [page]
        store = _store(client)

        names = [(i.name, i.is_dir) for i in store.list("b", "p/")]
        self.assertEqual(names, [("p/a", False), ("p/b", False)])
        self.assertEqual(client.list_calls[-1], ("b", {"prefix": "p/", "delimiter": None}))

        names = [(i.name, i.is_dir) for i in store.list("b", "p/", recursive=False)]
        self.assertEqual(names, [("p/a", False), ("p/b", False), ("p/sub/", True)])
        self.assertEqual(client.list_calls[-1], ("b", {"prefix": "p/", "delimiter": "/"}))

        self.assertEqual(list(store.list_prefixes("b", "p/")), ["p/sub/"])
        self.assertEqual(client.list_calls[-1], ("b", {"prefix": "p/", "delimiter": "/"}))

    def test_list_missing_bucket_is_not_found_on_iteration(self):
        client = _Client()
        client.list_error = NOT_FOUND
        gen = _store(client).list("nobucket")
        with self.assertRaises(StoreError) as ctx:
            next(gen)
        self.assertEqual((ctx.exception.code, ctx.exception.bucket), ("not_found", "nobucket"))

    def test_delete_missing_key_is_silent(self):
        client = _Client()
        client.blobs["k"] = _Blob("k", error=NOT_FOUND)
        _store(client).delete("b", "k")
        self.assertEqual(client.blobs["k"].calls, [("delete",)])

    def test_delete_other_errors_map(self):
        client = _Client()
        client.blobs["k"] = _Blob("k", error=gx.Forbidden("no"))
        with self.assertRaises(StoreError) as ctx:
            _store(client).delete("b", "k")
        self.assertEqual(ctx.exception.code, "access_denied")

    def test_delete_many_ignores_missing(self):
        client = _Client()
        client.blobs["a"] = _Blob("a")
        client.blobs["gone"] = _Blob("gone", error=NOT_FOUND)
        _store(client).delete_many("b", ["a", "gone"])
        self.assertEqual(client.deleted, ["a", "gone"])

    def test_delete_many_raises_on_real_failure(self):
        client = _Client()
        client.blobs["a"] = _Blob("a", error=gx.Forbidden("no"))
        with self.assertRaises(StoreError) as ctx:
            _store(client).delete_many("b", ["a"])
        self.assertEqual(ctx.exception.code, "access_denied")


class GcsBucketTests(SimpleTestCase):
    def test_ensure_bucket_idempotent_and_conflict_rechecks(self):
        client = _Client()
        store = GcsStore(client=client, location="EU", project="p")
        store.ensure_bucket("b")
        store.ensure_bucket("b")
        self.assertEqual(client.created, [("b", {"location": "EU", "project": "p"})])
        self.assertTrue(store.bucket_exists("b"))

        raced = _Client()
        raced.create_error = gx.Conflict("exists")
        raced_store = _store(raced)
        orig = raced.create_bucket

        def create_then_appear(name, **kw):
            raced.buckets.add(name)
            orig(name, **kw)

        raced.create_bucket = create_then_appear
        raced_store.ensure_bucket("b")

        owned = _Client()
        owned.create_error = gx.Conflict("taken")
        with self.assertRaises(StoreError) as ctx:
            _store(owned).ensure_bucket("b")
        self.assertEqual((ctx.exception.code, ctx.exception.bucket), ("already_exists", "b"))

    def test_bucket_exists_forbidden_is_access_denied(self):
        client = _Client()
        client.exists_error = gx.Forbidden("no")
        with self.assertRaises(StoreError) as ctx:
            _store(client).bucket_exists("b")
        self.assertEqual(ctx.exception.code, "access_denied")

    def test_label_validation_table(self):
        cases = {
            "upper-case key": {"Status": "x"},
            "space in value": {"status": "to do"},
            "digit first": {"1status": "x"},
            "65 labels": {f"k{i}": "v" for i in range(65)},
            "64-char value": {"k": "v" * 64},
            "64-char key": {"k" * 64: "v"},
            "empty key": {"": "v"},
        }
        for name, labels in cases.items():
            with self.subTest(name):
                client = _Client()
                with self.assertRaises(StoreError) as ctx:
                    _store(client).set_bucket_labels("b", labels)
                self.assertEqual(ctx.exception.code, "invalid")
                self.assertEqual(client.patched, [])
        with self.assertRaises(StoreError) as ctx:
            _store().set_bucket_labels("b", {"ok": "v", "Bad": "v"})
        self.assertIn("Bad", str(ctx.exception))

    def test_label_validation_accepts_limits(self):
        client = _Client()
        labels = {"a" + "-_0"[i % 3] + str(i): "" for i in range(63)}
        labels["k" * 63] = "v" * 63
        _store(client).set_bucket_labels("b", labels)
        self.assertEqual(client.patched, [labels])

    def test_labels_roundtrip_through_patch(self):
        client = _Client()
        store = _store(client)
        self.assertEqual(store.get_bucket_labels("b"), {})
        store.set_bucket_labels("b", {"status": "to-do"})
        self.assertEqual(client.patched, [{"status": "to-do"}])
        self.assertEqual(store.get_bucket_labels("b"), {"status": "to-do"})

    def test_set_labels_replaces_the_whole_set(self):
        client = _Client()
        store = _store(client)
        store.set_bucket_labels("b", {"a": "1", "b": "2"})
        store.set_bucket_labels("b", {"a": "1"})
        self.assertEqual(client.labels, {"a": "1"})
        self.assertEqual(store.get_bucket_labels("b"), {"a": "1"})

    def test_set_empty_labels_clears_all(self):
        client = _Client()
        client.labels = {"a": "1", "b": "2"}
        _store(client).set_bucket_labels("b", {})
        self.assertEqual(client.labels, {})

    def test_labels_map_errors(self):
        client = _Client()
        client.bucket = lambda name: (_ for _ in ()).throw(gx.NotFound("no bucket"))
        with self.assertRaises(StoreError) as ctx:
            _store(client).get_bucket_labels("b")
        self.assertEqual(ctx.exception.code, "not_found")

    def test_capabilities_exclude_free_form_bucket_tags(self):
        self.assertEqual(_store().capabilities,
                         frozenset({base.OBJECT_TAGS, base.LIFECYCLE, base.PRESIGN_PUT}))

    def test_health_reports_access_denied(self):
        client = _Client()
        self.assertTrue(_store(client).health().ok)
        client.list_buckets_error = gx.Forbidden("nope")
        status = _store(client).health()
        self.assertFalse(status.ok)
        self.assertTrue(status.detail.startswith("access_denied: "))

    def test_list_buckets_uses_project(self):
        client = _Client()
        client.buckets = {"b", "a"}
        store = _store(client)
        store._project = "p"
        self.assertEqual(store.list_buckets(), ["a", "b"])
        self.assertEqual(client.listed, [{"project": "p"}])


class _NoNetwork:
    def __getattr__(self, name):
        raise AssertionError(f"network used: {name}")


def _real_client():
    client = storage.Client(project="p", credentials=gcreds.AnonymousCredentials())
    client._http_internal = _NoNetwork()
    return client


def _key_credentials():
    pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    return service_account.Credentials.from_service_account_info({
        "type": "service_account", "client_email": "sa@p.iam.gserviceaccount.com", "private_key": pem,
        "token_uri": "https://oauth2.googleapis.com/token", "project_id": "p"})


class GcsPresignTests(SimpleTestCase):
    def _signed(self):
        return GcsStore(client=_real_client(), signing=Signer(credentials=_key_credentials()))

    def test_presign_get_with_key_signs_offline(self):
        url = self._signed().presign_get("b", "dir/a b.txt", timedelta(minutes=5), filename="r.pdf")
        parts, query = urlsplit(url), parse_qs(urlsplit(url).query)
        self.assertEqual(parts.netloc, "storage.googleapis.com")
        self.assertIn("/b/dir/a%20b.txt", parts.path)
        self.assertEqual(query["X-Goog-Expires"], ["300"])
        self.assertIn("filename", query["response-content-disposition"][0])

    def test_presign_get_without_filename_has_no_disposition(self):
        url = self._signed().presign_get("b", "k", timedelta(minutes=5))
        self.assertNotIn("response-content-disposition", url)

    def test_presign_put_signs_content_type(self):
        url = self._signed().presign_put("b", "k", timedelta(minutes=5), content_type="text/plain")
        self.assertIn("content-type", parse_qs(urlsplit(url).query)["X-Goog-SignedHeaders"][0])

    def test_presign_never_calls_the_network_with_a_key(self):
        store = self._signed()
        store.presign_get("b", "k", timedelta(seconds=60))
        store.presign_put("b", "k", timedelta(seconds=60))

    def test_presign_without_signing_raises_store_error(self):
        for signing in (None, Signer(), Signer(service_account_email="sa@p")):
            store = GcsStore(client=_real_client(), signing=signing)
            for call in (lambda: store.presign_get("b", "k", timedelta(1)),
                         lambda: store.presign_put("b", "k", timedelta(1))):
                with self.assertRaises(StoreError) as ctx:
                    call()
                self.assertEqual(ctx.exception.code, "invalid")
                self.assertIn("signing is not configured", str(ctx.exception))

    def test_keyless_signer_passes_email_and_token_and_refreshes(self):
        refreshed = []

        def token():
            refreshed.append(1)
            return "tok"

        seen = {}

        class Blob:
            name = "k"
            bucket = type("B", (), {"name": "b"})

            def generate_signed_url(self, **kwargs):
                seen.update(kwargs)
                return "https://signed"

        store = GcsStore(client=_real_client(),
                         signing=Signer(service_account_email="sa@p.iam.gserviceaccount.com", token=token))
        self.assertEqual(store._signed_url(Blob(), method="GET"), "https://signed")
        self.assertEqual(refreshed, [1])
        self.assertEqual(seen["service_account_email"], "sa@p.iam.gserviceaccount.com")
        self.assertEqual(seen["access_token"], "tok")
        self.assertEqual(seen["version"], "v4")
        self.assertNotIn("credentials", seen)

    def test_keyless_iam_failure_maps(self):
        class Blob:
            name = "k"
            bucket = type("B", (), {"name": "b"})

            def generate_signed_url(self, **kwargs):
                raise gx.Forbidden("iam")

        store = GcsStore(client=_real_client(), signing=Signer(service_account_email="e", token=lambda: "t"))
        with self.assertRaises(StoreError) as ctx:
            store._signed_url(Blob(), method="GET")
        self.assertEqual(ctx.exception.code, "access_denied")

    def test_non_signing_credentials_are_invalid_config_not_unavailable(self):
        store = GcsStore(client=_real_client(), signing=Signer(credentials=gcreds.AnonymousCredentials()))
        with self.assertRaises(StoreError) as ctx:
            store.presign_get("b", "k", timedelta(minutes=5))
        self.assertEqual(ctx.exception.code, "invalid")
        self.assertIn("signing is not configured", str(ctx.exception))

    def test_expiry_over_seven_days_is_invalid(self):
        with self.assertRaises(StoreError) as ctx:
            self._signed().presign_get("b", "k", timedelta(days=8))
        self.assertEqual(ctx.exception.code, "invalid")

    def test_filenames_are_encoded_in_disposition(self):
        for name, expected in (("résumé.pdf", "r%C3%A9sum%C3%A9.pdf"),
                               ('a\r\nb";c.txt', "a%0D%0Ab%22%3Bc.txt")):
            url = self._signed().presign_get("b", "k", timedelta(minutes=5), filename=name)
            self.assertFalse(any(c in url for c in "\r\n\" ;"), url)
            disposition = parse_qs(urlsplit(url).query)["response-content-disposition"][0]
            self.assertIn("filename*=UTF-8''" + expected, disposition)
            self.assertNotIn("\r", disposition)
            self.assertNotIn("\n", disposition)
