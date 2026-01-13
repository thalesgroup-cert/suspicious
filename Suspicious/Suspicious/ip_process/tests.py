from django.test import TestCase
from unittest.mock import patch

from ip_process.models import IP
from ip_process.ip_utils.ip_handler import IPHandler


class IPModelTests(TestCase):

    def test_str_representation(self):
        obj = IP.objects.create(address="8.8.8.8")
        self.assertEqual(str(obj), "8.8.8.8")

    def test_default_fields(self):
        obj = IP.objects.create(address="1.1.1.1")
        self.assertEqual(obj.ioc_score, 5)
        self.assertEqual(obj.ioc_confidence, 0)
        self.assertEqual(obj.ioc_level, "info")
        self.assertEqual(obj.times_sent, 0)


class IPHandlerValidationTests(TestCase):

    def setUp(self):
        self.handler = IPHandler()

    def test_validate_ip_public_ipv4(self):
        result = self.handler.validate_ip("8.8.8.8")
        self.assertEqual(result, "Public IPv4")

    def test_validate_ip_private_ipv4(self):
        result = self.handler.validate_ip("192.168.0.10")
        self.assertEqual(result, "Private IPv4")

    def test_validate_ip_private_ipv6(self):
        result = self.handler.validate_ip("::")
        self.assertEqual(result, "Private IPv6")

    def test_validate_ip_invalid(self):
        result = self.handler.validate_ip("not_an_ip")
        self.assertIsNone(result)


class IPHandlerProcessingTests(TestCase):

    def setUp(self):
        self.handler = IPHandler()

    def test_handle_ip_creates_new_public_ip(self):
        obj = self.handler.handle_ip("8.8.8.8")
        self.assertIsNotNone(obj)
        self.assertEqual(obj.address, "8.8.8.8")
        self.assertEqual(obj.times_sent, 0)

    def test_handle_ip_updates_existing_public_ip(self):
        existing = IP.objects.create(address="8.8.8.8", times_sent=0)

        self.handler.handle_ip("8.8.8.8")
        existing.refresh_from_db()

        self.assertEqual(existing.times_sent, 1)

    def test_handle_ip_ignores_private_ip(self):
        obj = self.handler.handle_ip("192.168.1.1")
        self.assertIsNone(obj)
        self.assertEqual(IP.objects.count(), 0)

    def test_handle_ip_invalid_returns_none(self):
        obj = self.handler.handle_ip("invalid")
        self.assertIsNone(obj)
        self.assertEqual(IP.objects.count(), 0)


class IPHandlerExceptionTests(TestCase):

    @patch("ip_process.ip_utils.ip_handler.IP.objects.get_or_create")
    def test_handle_ip_db_exception_return_none(self, mock_get):
        mock_get.side_effect = Exception("DB failure")

        handler = IPHandler()
        result = handler.handle_ip("8.8.8.8")

        self.assertIsNone(result)
