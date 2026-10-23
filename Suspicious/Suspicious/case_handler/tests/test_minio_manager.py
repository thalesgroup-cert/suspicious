from datetime import timedelta
from pathlib import Path
import tempfile
from unittest import mock

from django.test import SimpleTestCase

from case_handler.case_utils.form_handlers.mail.minio import MinioManager
from common.storage import FakeObjectStore

MOD = "case_handler.case_utils.form_handlers.mail.minio"
WEEK = timedelta(days=7)


class GeneratePresignedUrlTest(SimpleTestCase):
    def _manager(self, store=None, presign=None):
        with mock.patch(f"{MOD}.get_store", return_value=store or FakeObjectStore()), \
                mock.patch(f"{MOD}.get_presign_store", return_value=presign or FakeObjectStore()):
            return MinioManager()

    def test_get_uses_presign_store_not_internal_store(self):
        presign = mock.MagicMock()
        presign.presign_get.return_value = "https://public/signed"
        store = mock.MagicMock()
        manager = self._manager(store, presign)

        url = manager.generate_presigned_url("bucket", "obj.eml")

        self.assertEqual(url, "https://public/signed")
        presign.presign_get.assert_called_once_with("bucket", "obj.eml", WEEK)
        store.presign_get.assert_not_called()

    def test_put_uses_presign_store(self):
        presign = mock.MagicMock()
        presign.presign_put.return_value = "https://public/put"
        manager = self._manager(presign=presign)

        url = manager.generate_presigned_url("bucket", "obj.eml", method="put")

        self.assertEqual(url, "https://public/put")

    def test_returns_none_when_presign_store_unavailable(self):
        with mock.patch(f"{MOD}.get_store", return_value=FakeObjectStore()), \
                mock.patch(f"{MOD}.get_presign_store", side_effect=Exception("boom")):
            manager = MinioManager()

        self.assertIsNone(manager.generate_presigned_url("bucket", "obj.eml"))


class UploadDirectoryTest(SimpleTestCase):
    def _upload(self, store, default_tags=None):
        with mock.patch(f"{MOD}.get_store", return_value=store), \
                mock.patch(f"{MOD}.get_presign_store", return_value=store), \
                tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "sub").mkdir()
            (Path(tmp) / "sub" / "a.eml").write_bytes(b"hello")
            MinioManager().upload_directory(Path(tmp), "bkt", default_tags=default_tags)

    def test_new_bucket_gets_todo_label_and_objects(self):
        store = FakeObjectStore()
        self._upload(store)
        self.assertEqual(store.get_bucket_labels("bkt"), {"Status": "To Do"})
        with store.open("bkt", "sub/a.eml") as s:
            self.assertEqual(s.read(), b"hello")

    def test_existing_bucket_labels_are_left_alone(self):
        store = FakeObjectStore()
        store.ensure_bucket("bkt")
        store.set_bucket_labels("bkt", {"Status": "Done"})
        self._upload(store)
        self.assertEqual(store.get_bucket_labels("bkt"), {"Status": "Done"})

    def test_object_tags_are_passed_to_put(self):
        store = FakeObjectStore()
        with mock.patch.object(store, "put", wraps=store.put) as put:
            self._upload(store, default_tags={"Status": "To Do"})
        self.assertEqual(put.call_args.kwargs["tags"], {"Status": "To Do"})
