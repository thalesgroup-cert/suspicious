import io
import zipfile
from types import SimpleNamespace

from django.test import SimpleTestCase
from rest_framework.exceptions import NotFound

from api.storage import StorageClient, open_chunks
from api.views.downloads import DownloadCaseArchiveView, StorageUnavailable
from common.storage import FakeObjectStore, StoreError


def _storage(store):
    sc = StorageClient.__new__(StorageClient)
    sc.client = store
    return sc


class ArchiveZipTests(SimpleTestCase):
    def _build(self, store):
        view = DownloadCaseArchiveView()
        return view._build_zip_archive(
            storage=_storage(store),
            case=SimpleNamespace(pk=1),
            archive=SimpleNamespace(bucket_name="arch"),
        )

    def test_zips_every_object(self):
        store = FakeObjectStore()
        store.ensure_bucket("arch")
        store.put("arch", "a.eml", io.BytesIO(b"AAA"))
        store.put("arch", "b/c.txt", io.BytesIO(b"CCC"))
        with zipfile.ZipFile(self._build(store)) as z:
            self.assertEqual({n: z.read(n) for n in z.namelist()}, {"a.eml": b"AAA", "b/c.txt": b"CCC"})

    def test_missing_bucket_is_503(self):
        with self.assertRaises(StorageUnavailable):
            self._build(FakeObjectStore())

    def test_empty_bucket_is_404(self):
        store = FakeObjectStore()
        store.ensure_bucket("arch")
        with self.assertRaises(NotFound):
            self._build(store)


class _FlakyOpen(FakeObjectStore):
    def __init__(self, code):
        super().__init__()
        self.code = code

    def open(self, bucket, key):
        if key == "bad":
            raise StoreError(self.code, "boom")
        return super().open(bucket, key)


class ArchivePartialFailureTests(SimpleTestCase):
    _build = ArchiveZipTests._build

    def _store(self, code):
        store = _FlakyOpen(code)
        store.ensure_bucket("arch")
        store.put("arch", "a.eml", io.BytesIO(b"AAA"))
        store.put("arch", "bad", io.BytesIO(b"x"))
        return store

    def test_not_found_object_is_skipped(self):
        with zipfile.ZipFile(self._build(self._store("not_found"))) as z:
            self.assertEqual(z.namelist(), ["a.eml"])

    def test_other_errors_mid_archive_are_503(self):
        for code in ("unavailable", "access_denied"):
            with self.subTest(code=code), self.assertRaises(StorageUnavailable):
                self._build(self._store(code))


class StreamObjectTests(SimpleTestCase):
    def test_outage_is_503_not_404(self):
        sc = _storage(_FlakyOpen("unavailable"))
        with self.assertRaises(StorageUnavailable):
            sc.stream_object("b", "bad")

    def test_close_before_iteration_closes_the_stream(self):
        events = []

        class CM:
            def __enter__(self):
                return SimpleNamespace(iter_chunks=lambda n: iter([b"x"]))

            def __exit__(self, *exc):
                events.append("closed")

        store = FakeObjectStore()
        store.open = lambda bucket, key: CM()
        chunks = open_chunks(store, "b", "k")
        self.assertEqual(events, [])
        chunks.close()
        self.assertEqual(events, ["closed"])

    def test_close_after_exhaustion_closes_once(self):
        events = []

        class CM:
            def __enter__(self):
                return SimpleNamespace(iter_chunks=lambda n: iter([b"x"]))

            def __exit__(self, *exc):
                events.append("closed")

        store = FakeObjectStore()
        store.open = lambda bucket, key: CM()
        chunks = open_chunks(store, "b", "k")
        self.assertEqual(list(chunks), [b"x"])
        chunks.close()
        self.assertEqual(events, ["closed"])

    def test_streams_and_404s(self):
        store = FakeObjectStore()
        store.ensure_bucket("b")
        store.put("b", "k", io.BytesIO(b"xyz"))
        sc = _storage(store)
        resp = sc.stream_object("b", "k")
        self.assertEqual(b"".join(resp.streaming_content), b"xyz")
        with self.assertRaises(NotFound):
            sc.stream_object("b", "nope")
