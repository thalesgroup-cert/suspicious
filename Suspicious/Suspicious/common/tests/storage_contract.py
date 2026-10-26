import io
import tempfile
from datetime import timedelta
from pathlib import Path

from common.storage import base
from common.storage.base import StoreError


class StoreContract:
    """Behaviour every ObjectStore must show. Subclass with SimpleTestCase and
    provide make_store() and bucket."""

    bucket = "contract-bucket"
    labels_supported = True

    def make_store(self):
        raise NotImplementedError

    def setUp(self):
        super().setUp()
        self.store = self.make_store()
        self.store.ensure_bucket(self.bucket)

    def _put(self, key, data=b"x"):
        self.store.put(self.bucket, key, io.BytesIO(data), length=len(data))

    def assertNotFound(self, fn, *args, **kwargs):
        with self.assertRaises(StoreError) as ctx:
            fn(*args, **kwargs)
        self.assertEqual(ctx.exception.code, "not_found")

    def assertOpenNotFound(self, bucket, key):
        # a provider may fail on open() itself or only on entering the context
        with self.assertRaises(StoreError) as ctx:
            with self.store.open(bucket, key):
                pass
        self.assertEqual(ctx.exception.code, "not_found")

    def test_put_open_roundtrip(self):
        self._put("a.eml", b"hello")
        with self.store.open(self.bucket, "a.eml") as stream:
            self.assertEqual(stream.read(), b"hello")

    def test_open_streams_in_chunks(self):
        self._put("big.bin", b"z" * (3 << 20))
        with self.store.open(self.bucket, "big.bin") as stream:
            chunks = list(stream.iter_chunks(1 << 20))
        self.assertEqual(len(chunks), 3)

    def test_stat_reports_size_and_etag(self):
        self._put("a.eml", b"hello")
        info = self.store.stat(self.bucket, "a.eml")
        self.assertEqual(info.size, 5)
        self.assertTrue(info.etag)

    def test_stat_missing_key_is_not_found(self):
        self.assertNotFound(self.store.stat, self.bucket, "nope")

    def test_missing_bucket_is_not_found(self):
        self.assertNotFound(lambda: list(self.store.list("no-such-bucket")))
        self.assertNotFound(self.store.stat, "no-such-bucket", "k")
        self.assertOpenNotFound("no-such-bucket", "k")

    def test_open_missing_key_is_not_found(self):
        self.assertOpenNotFound(self.bucket, "nope")

    def test_list_prefix_and_recursive(self):
        for key in ("d/a", "d/sub/b", "other"):
            self._put(key)
        names = {o.name for o in self.store.list(self.bucket, "d/")}
        self.assertEqual(names, {"d/a", "d/sub/b"})
        shallow = list(self.store.list(self.bucket, "d/", recursive=False))
        self.assertEqual({o.name for o in shallow if not o.is_dir}, {"d/a"})
        self.assertEqual({o.name for o in shallow if o.is_dir}, {"d/sub/"})

    def test_list_prefixes_returns_folders(self):
        for key in ("d/a", "e/b", "top"):
            self._put(key)
        self.assertEqual(sorted(self.store.list_prefixes(self.bucket)), ["d/", "e/"])

    def test_delete_and_delete_many(self):
        for key in ("a", "b", "c"):
            self._put(key)
        self.store.delete(self.bucket, "a")
        self.assertNotFound(self.store.stat, self.bucket, "a")
        self.store.delete_many(self.bucket, ["b", "c"])
        self.assertEqual(list(self.store.list(self.bucket)), [])

    def test_ensure_bucket_is_idempotent(self):
        self.store.ensure_bucket(self.bucket)
        self.assertTrue(self.store.bucket_exists(self.bucket))
        self.assertIn(self.bucket, self.store.list_buckets())

    def test_bucket_labels_roundtrip(self):
        if not self.labels_supported:
            self.skipTest("this backend does not persist bucket labels")
        labels = ({"Status": "To Do"} if base.FREE_FORM_BUCKET_TAGS in self.store.capabilities
                  else {"status": "to-do"})
        self.store.set_bucket_labels(self.bucket, labels)
        self.assertEqual(self.store.get_bucket_labels(self.bucket), labels)

    def test_awkward_keys_roundtrip(self):
        key = "a b/ü+#%.eml"
        self._put(key, b"k")
        self.assertIn(key, [o.name for o in self.store.list(self.bucket)])
        self.assertEqual(self.store.stat(self.bucket, key).size, 1)

    def test_download_writes_file(self):
        self._put("a.eml", b"hello")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "out.eml"
            self.store.download(self.bucket, "a.eml", str(path))
            self.assertEqual(path.read_bytes(), b"hello")

    def test_presign_get_contains_key_and_expiry(self):
        url = self.store.presign_get(self.bucket, "a.eml", timedelta(minutes=5))
        self.assertIn("a.eml", url)
        self.assertIn("300", url)
