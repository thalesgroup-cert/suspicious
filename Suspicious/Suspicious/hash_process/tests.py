from django.test import TestCase
from unittest.mock import patch, MagicMock

from hash_process.models import Hash
from hash_process.hash_utils.hash_handler import HashHandler


class HashModelTests(TestCase):

    def test_str_representation(self):
        obj = Hash.objects.create(value="abcd1234")
        self.assertEqual(str(obj), "abcd1234")

    def test_default_fields(self):
        obj = Hash.objects.create(value="1234abcd")
        self.assertEqual(obj.ioc_score, 5)
        self.assertEqual(obj.ioc_confidence, 0)
        self.assertEqual(obj.ioc_level, "info")
        self.assertEqual(obj.hashtype, "sha256 hash")
        self.assertEqual(obj.times_sent, 0)

    def test_update_allow_listed(self):
        obj = Hash.objects.create(value="safehash")
        obj.update_allow_listed()
        obj.refresh_from_db()
        self.assertEqual(obj.ioc_score, 0)
        self.assertEqual(obj.ioc_confidence, 100)
        self.assertEqual(obj.ioc_level, "SAFE-ALLOW_LISTED")


class HashHandlerValidationTests(TestCase):

    def setUp(self):
        self.handler = HashHandler()

    def test_validate_hash_detected(self):
        self.handler.hashid = MagicMock()
        mock_hash_type = MagicMock()
        mock_hash_type.name = "SHA256"  # Explicit string
        self.handler.hashid.identifyHash.return_value = iter([mock_hash_type])

        result = self.handler.validate_hash("abcd1234")
        self.assertEqual(result, "SHA256")

    def test_validate_hash_ssdeep(self):
        ssdeep = "3:abc:def"
        result = self.handler.validate_hash(ssdeep)
        self.assertEqual(result, "SSDEEP")

    def test_validate_hash_empty_ssdeep_returns_none(self):
        result = self.handler.validate_hash("0:")
        self.assertIsNone(result)

    def test_validate_hash_invalid_returns_none(self):
        self.handler.hashid = MagicMock()
        self.handler.hashid.identifyHash.return_value = iter([])

        result = self.handler.validate_hash("invalidhash")
        self.assertIsNone(result)


class HashHandlerProcessingTests(TestCase):

    def setUp(self):
        self.handler = HashHandler()

    @patch.object(HashHandler, '_create_or_update_hash')
    @patch.object(HashHandler, 'validate_hash')
    def test_handle_hash_creates_new(self, mock_validate, mock_create):
        mock_validate.return_value = "SHA256"
        mock_instance = MagicMock()
        mock_create.return_value = mock_instance

        result = self.handler.handle_hash("abcd1234")
        self.assertEqual(result, mock_instance)
        mock_create.assert_called_once_with(hash_value="abcd1234", hash_type="SHA256")

    @patch.object(HashHandler, '_create_or_update_hash')
    @patch.object(HashHandler, 'validate_hash')
    def test_handle_hash_invalid_returns_none(self, mock_validate, mock_create):
        mock_validate.return_value = None
        result = self.handler.handle_hash("invalid")
        self.assertIsNone(result)
        mock_create.assert_not_called()


class HashHandlerDatabaseTests(TestCase):

    def setUp(self):
        self.handler = HashHandler()

    def test_create_or_update_hash_new(self):
        h = "newhash"
        instance = self.handler._create_or_update_hash(hash_value=h, hash_type="SHA256")
        self.assertIsInstance(instance, Hash)
        self.assertEqual(instance.value, h)
        self.assertEqual(instance.hashtype, "SHA256")
        self.assertEqual(instance.times_sent, 0)

    def test_create_or_update_hash_existing_increments_times_sent(self):
        h = "existinghash"
        existing = Hash.objects.create(value=h, hashtype="SHA256", times_sent=0)

        instance = self.handler._create_or_update_hash(hash_value=h, hash_type="SHA256")
        existing.refresh_from_db()

        self.assertEqual(existing.times_sent, 1)
        self.assertEqual(instance.value, h)


class HashHandlerExceptionTests(TestCase):

    @patch("hash_process.hash_utils.hash_handler.Hash.objects.get_or_create")
    def test_create_or_update_hash_exception_returns_none(self, mock_get):
        mock_get.side_effect = Exception("DB failure")
        handler = HashHandler()
        result = handler._create_or_update_hash("badhash", "SHA256")
        self.assertIsNone(result)
