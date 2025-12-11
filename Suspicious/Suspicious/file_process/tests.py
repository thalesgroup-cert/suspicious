from django.test import TestCase
from unittest.mock import patch, MagicMock

from file_process.models import File, HashFromFile
from file_process.file_utils.file_handler import FileHandler
from hash_process.models import Hash


class FileModelTests(TestCase):

    def setUp(self):
        self.hash = Hash.objects.create(value="abcd1234")

    def test_str_representation(self):
        f = File.objects.create(
            linked_hash=self.hash,
            file_path="files/testfile.txt",
            tmp_path="/tmp/testfile.txt"
        )
        self.assertEqual(str(f), "files/testfile.txt")

    def test_default_fields(self):
        f = File.objects.create(
            linked_hash=self.hash,
            file_path="files/testfile.txt",
            tmp_path="/tmp/testfile.txt"
        )
        self.assertEqual(f.file_score, 5)
        self.assertEqual(f.file_confidence, 0)
        self.assertEqual(f.file_level, "info")
        self.assertEqual(f.filetype, "unknown filetype")
        self.assertEqual(f.size, 0)
        self.assertEqual(f.times_sent, 0)

    def test_update_allow_listed(self):
        f = File.objects.create(
            linked_hash=self.hash,
            file_path="files/testfile.txt",
            tmp_path="/tmp/testfile.txt"
        )
        f.update_allow_listed()
        f.refresh_from_db()
        self.assertEqual(f.file_score, 0)
        self.assertEqual(f.file_confidence, 100)
        self.assertEqual(f.file_level, "SAFE-ALLOW_LISTED")


class FileHandlerProcessingTests(TestCase):

    def setUp(self):
        self.handler = FileHandler()
        self.hash = Hash.objects.create(value="abcd1234")

    @patch("file_process.file_utils.file_handler.FileHandler.hash_file")
    def test_handle_file_creates_new_file_and_hash(self, mock_hash_file):
        mock_hash_file.return_value = "hash123"
        file_mock = MagicMock()
        file_mock.name = "files/testfile.txt"
        file_mock.temporary_file_path.return_value = "/tmp/testfile.txt"

        file_instance, hash_instance = FileHandler.handle_file(file=file_mock)
        self.assertIsInstance(file_instance, File)
        self.assertIsInstance(hash_instance, Hash)
        self.assertEqual(file_instance.linked_hash, hash_instance)
        self.assertIn("files/testfile.txt", file_instance.file_path.name if hasattr(file_instance.file_path, 'name') else file_instance.file_path)

    @patch("file_process.file_utils.file_handler.FileHandler.hash_file")
    def test_handle_file_invalid_hash_returns_none(self, mock_hash_file):
        mock_hash_file.return_value = None
        file_mock = MagicMock()
        file_mock.name = "files/testfile.txt"
        file_mock.temporary_file_path.return_value = "/tmp/testfile.txt"

        file_instance, hash_instance = FileHandler.handle_file(file=file_mock)
        self.assertIsNone(file_instance)
        self.assertIsNone(hash_instance)

    def test_handle_file_no_args_returns_none(self):
        file_instance, hash_instance = FileHandler.handle_file()
        self.assertIsNone(file_instance)
        self.assertIsNone(hash_instance)

    def test_create_or_update_existing_file_increments_times_sent(self):
        # Create a file linked to a hash
        file_instance = File.objects.create(
            linked_hash=self.hash,
            file_path="files/testfile.txt",
            tmp_path="/tmp/testfile.txt",
            times_sent=0
        )
        # Patch hash_file to return the same hash
        with patch.object(FileHandler, 'hash_file', return_value=self.hash.value):
            f_inst, h_inst = FileHandler.handle_file(file=MagicMock(
                name="files/testfile.txt",
                temporary_file_path=MagicMock(return_value="/tmp/testfile.txt")
            ))
            file_instance.refresh_from_db()
            self.assertEqual(file_instance.times_sent, 1)

    def test_hash_from_file_relation_created(self):
        file_mock = MagicMock()
        file_mock.name = "files/testfile.txt"
        file_mock.temporary_file_path.return_value = "/tmp/testfile.txt"
        with patch.object(FileHandler, 'hash_file', return_value="hash123"):
            file_instance, hash_instance = FileHandler.handle_file(file=file_mock)
            relation = HashFromFile.objects.filter(file=file_instance, hash=hash_instance).first()
            self.assertIsNotNone(relation)


class FileHandlerExceptionTests(TestCase):

    def setUp(self):
        self.handler = FileHandler()
        self.hash = Hash.objects.create(value="abcd1234")

    @patch("file_process.file_utils.file_handler.File.objects.create")
    def test_create_new_file_raises_exception_returns_none(self, mock_create):
        mock_create.side_effect = Exception("DB failure")
        file_mock = MagicMock()
        file_mock.name = "files/testfile.txt"
        file_mock.temporary_file_path.return_value = "/tmp/testfile.txt"

        with self.assertRaises(Exception):
            self.handler._create_new_file_instance("files/testfile.txt", "/tmp/testfile.txt", self.hash, 100)

    @patch("file_process.file_utils.file_handler.File.objects.filter")
    def test_update_existing_file_raises_exception(self, mock_filter):
        file_instance = File.objects.create(
            linked_hash=self.hash,
            file_path="files/testfile.txt",
            tmp_path="/tmp/testfile.txt",
            times_sent=0
        )
        mock_filter.return_value.first.return_value = file_instance
        with patch.object(FileHandler, '_update_existing_file_instance', side_effect=Exception("DB failure")):
            with self.assertRaises(Exception):
                self.handler._handle_file_logic("files/testfile.txt", "/tmp/testfile.txt", self.hash.value)
