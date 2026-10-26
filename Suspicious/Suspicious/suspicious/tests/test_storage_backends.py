"""Tests for the custom MinIO-backed Django storage backends.

These exercise the real save/open/exists/delete/url orchestration against
an in-memory FakeObjectStore (the only unavoidable external boundary),
so no live RustFS/MinIO is required. The backends wrap the project's
ObjectStore interface (FakeObjectStore here).
"""
import tempfile

from django.core.files.base import ContentFile
from django.core.files.storage import FileSystemStorage
from unittest import mock

from django.test import TestCase

from common.storage import FakeObjectStore

from suspicious.storage_backends import DualStorage, MinioMediaStorage


def _fake_store():
    store = FakeObjectStore()
    store.ensure_bucket("media")
    return store


def _minio_storage():
    return MinioMediaStorage(client=_fake_store(), bucket="media")


class MinioMediaStorageTest(TestCase):
    def test_save_then_open_roundtrips_bytes(self):
        storage = _minio_storage()
        name = storage.save("dir/file.txt", ContentFile(b"hello world"))
        self.assertEqual(name, "dir/file.txt")
        self.assertEqual(storage.open(name).read(), b"hello world")

    def test_exists_true_only_when_saved(self):
        storage = _minio_storage()
        self.assertFalse(storage.exists("nope.txt"))
        storage.save("yes.txt", ContentFile(b"x"))
        self.assertTrue(storage.exists("yes.txt"))

    def test_delete_removes_object(self):
        storage = _minio_storage()
        storage.save("gone.txt", ContentFile(b"bye"))
        storage.delete("gone.txt")
        self.assertFalse(storage.exists("gone.txt"))

    def test_size_reports_byte_length(self):
        storage = _minio_storage()
        storage.save("s.bin", ContentFile(b"12345"))
        self.assertEqual(storage.size("s.bin"), 5)

    def test_listdir_splits_dirs_and_files(self):
        storage = _minio_storage()
        storage.save("top.txt", ContentFile(b"1"))
        storage.save("sub/inner.txt", ContentFile(b"2"))
        self.assertEqual(storage.listdir(""), (["sub"], ["top.txt"]))
        self.assertEqual(storage.listdir("sub"), ([], ["inner.txt"]))

    def test_default_client_comes_from_get_store_and_creates_bucket(self):
        fake = FakeObjectStore()
        with mock.patch("suspicious.storage_backends.get_store", return_value=fake):
            storage = MinioMediaStorage(bucket="fresh")
            storage.save("a.txt", ContentFile(b"x"))
        self.assertTrue(fake.bucket_exists("fresh"))
        self.assertTrue(storage.exists("a.txt"))

    def test_url_is_media_url_joined(self):
        storage = _minio_storage()
        self.assertEqual(storage.url("a/b.png"), "/media/a/b.png")


class DualStorageTest(TestCase):
    def _dual(self, *, dual_write):
        self.tmp = tempfile.mkdtemp()
        primary = MinioMediaStorage(client=_fake_store(), bucket="media")
        secondary = FileSystemStorage(location=self.tmp, base_url="/media/")
        return DualStorage(primary=primary, secondary=secondary, dual_write=dual_write)

    def test_save_writes_primary_only_when_dual_write_off(self):
        ds = self._dual(dual_write=False)
        ds.save("x.txt", ContentFile(b"data"))
        self.assertTrue(ds.primary.exists("x.txt"))
        self.assertFalse(ds.secondary.exists("x.txt"))

    def test_save_writes_both_when_dual_write_on(self):
        ds = self._dual(dual_write=True)
        ds.save("x.txt", ContentFile(b"data"))
        self.assertTrue(ds.primary.exists("x.txt"))
        self.assertTrue(ds.secondary.exists("x.txt"))

    def test_open_falls_back_to_secondary(self):
        ds = self._dual(dual_write=False)
        ds.secondary.save("legacy.txt", ContentFile(b"old"))
        self.assertTrue(ds.exists("legacy.txt"))
        self.assertEqual(ds.open("legacy.txt").read(), b"old")

    def test_exists_checks_both_stores(self):
        ds = self._dual(dual_write=False)
        ds.primary.save("p.txt", ContentFile(b"p"))
        ds.secondary.save("s.txt", ContentFile(b"s"))
        self.assertTrue(ds.exists("p.txt"))
        self.assertTrue(ds.exists("s.txt"))
        self.assertFalse(ds.exists("missing.txt"))
