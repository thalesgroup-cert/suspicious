from django.test import TestCase
from unittest.mock import patch, MagicMock

from file_process.models import File, HashFromFile
from file_process.file_utils.file_handler import (
    MAX_OTHER_NAMES,
    FileHandler,
    format_other_names,
    parse_other_names,
)
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
        file_instance = File.objects.create(
            linked_hash=self.hash,
            file_path="files/testfile.txt",
            tmp_path="/tmp/testfile.txt",
            times_sent=0
        )
        with patch.object(FileHandler, 'hash_file', return_value=self.hash.value):
            _f_inst, _h_inst = FileHandler.handle_file(file=MagicMock(
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

    def test_handle_file_mail_branch_reads_size_from_real_absolute_path(self):
        """Regression: the `mail=` branch passes an already-absolute path
        (e.g. /tmp/emailAnalysis/<sub>/<id>/x.eml). Size must be read from
        that path directly, not from "/tmp/" + it (a double prefix that
        always 404s and silently stores size=0)."""
        import os
        import tempfile
        with tempfile.NamedTemporaryFile(dir="/tmp", suffix=".eml", delete=True) as tf:
            tf.write(b"a body of a known length")
            tf.flush()
            real_size = os.path.getsize(tf.name)

            with patch.object(FileHandler, 'hash_file', return_value="mailhash123"):
                file_instance, hash_instance = FileHandler.handle_file(mail=tf.name)

        self.assertIsInstance(file_instance, File)
        self.assertEqual(file_instance.size, real_size)
        self.assertNotEqual(file_instance.size, 0)


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
                self.handler._handle_file_logic("files/testfile.txt", "/tmp/testfile.txt", self.hash.value, "/tmp/testfile.txt")


class OtherNamesTests(TestCase):
    """File.other_names must stay a small alias list.

    Regression: the old code re-split its own ``str(list)`` output on commas,
    which added a layer of quotes/escapes per update, so a file re-reported
    under another name (e.g. the same signature image attached as
    ``0_WRD0001.jpg`` to every mail) doubled other_names each time. After ~23
    updates one UPDATE exceeded MariaDB's max_allowed_packet (error 1153), the
    mail was not stored and the submission failed.
    """

    def setUp(self):
        self.hash = Hash.objects.create(value="sig-image-hash")
        self.file = File.objects.create(
            linked_hash=self.hash, file_path="WRD0001.jpg", tmp_path="/tmp/a", other_names=""
        )

    def _report_again(self, name):
        FileHandler()._handle_file_logic(name, "/tmp/" + name, self.hash.value, "/nonexistent/" + name)
        self.file.refresh_from_db()

    def test_same_alias_reported_many_times_does_not_grow(self):
        for _ in range(60):
            self._report_again("0_WRD0001.jpg")
        self.assertEqual(self.file.other_names, '["0_WRD0001.jpg"]')
        self.assertEqual(self.file.times_sent, 60)

    def test_distinct_aliases_are_kept_up_to_the_cap(self):
        for i in range(MAX_OTHER_NAMES + 20):
            self._report_again(f"copy_{i}.jpg")
        names = parse_other_names(self.file.other_names)
        self.assertEqual(len(names), MAX_OTHER_NAMES)
        self.assertEqual(names[:2], ["copy_0.jpg", "copy_1.jpg"])

    def test_legacy_str_list_is_read_and_extended(self):
        self.file.other_names = "['a.jpg', 'b.jpg']"
        self.file.save()
        self._report_again("c.jpg")
        self.assertEqual(parse_other_names(self.file.other_names), ["a.jpg", "b.jpg", "c.jpg"])

    def test_blown_up_value_is_healed_even_when_the_name_is_unchanged(self):
        # ~10 MB of nested escapes, as the old code produced.
        self.file.other_names = "[" + "\\'0_WRD0001.jpg\\'," * 500_000 + "]"
        self.file.save()
        self._report_again("WRD0001.jpg")  # same name as file_path: nothing to add
        self.assertEqual(self.file.other_names, "")
        self.assertEqual(self.file.times_sent, 1)

    def test_blown_up_value_is_healed_and_new_alias_recorded(self):
        self.file.other_names = "[" + "\\'x\\'," * 500_000 + "]"
        self.file.save()
        self._report_again("0_WRD0001.jpg")
        self.assertEqual(self.file.other_names, '["0_WRD0001.jpg"]')

    def test_update_does_not_resend_untouched_columns(self):
        self.file.file_score = 9
        self.file.save()
        File.objects.filter(pk=self.file.pk).update(file_score=1)  # changed behind our back
        self._report_again("WRD0001.jpg")
        self.assertEqual(self.file.file_score, 1)  # save() of every column would have reset it to 9


class ParseOtherNamesTests(TestCase):
    def test_empty_and_garbage(self):
        for raw in (None, "", "not a list", "{'a': 1}", "[", 42):
            self.assertEqual(parse_other_names(raw), [], raw)

    def test_json_and_legacy_forms(self):
        self.assertEqual(parse_other_names('["a", "b"]'), ["a", "b"])
        self.assertEqual(parse_other_names("['a', 'b']"), ["a", "b"])

    def test_damaged_legacy_quotes_are_stripped_and_deduplicated(self):
        self.assertEqual(parse_other_names("[\"'0_x.jpg'\", '0_x.jpg', \"'0_x.jpg'\"]"), ["0_x.jpg"])

    def test_oversized_value_is_dropped(self):
        self.assertEqual(parse_other_names("[" + "'a'," * 5000 + "]"), [])

    def test_format_round_trip(self):
        names = ["it's.jpg", "naïve.png", "a b.txt"]
        self.assertEqual(parse_other_names(format_other_names(names)), names)
        self.assertEqual(format_other_names([]), "")
