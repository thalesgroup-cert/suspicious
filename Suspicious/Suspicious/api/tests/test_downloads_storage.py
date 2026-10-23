import io
import zipfile
from types import SimpleNamespace

from django.test import SimpleTestCase
from rest_framework.exceptions import NotFound

from api.storage import StorageClient
from api.views.downloads import DownloadCaseArchiveView, StorageUnavailable
from common.storage import FakeObjectStore


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


class StreamObjectTests(SimpleTestCase):
    def test_streams_and_404s(self):
        store = FakeObjectStore()
        store.ensure_bucket("b")
        store.put("b", "k", io.BytesIO(b"xyz"))
        sc = _storage(store)
        resp = sc.stream_object("b", "k")
        self.assertEqual(b"".join(resp.streaming_content), b"xyz")
        with self.assertRaises(NotFound):
            sc.stream_object("b", "nope")
