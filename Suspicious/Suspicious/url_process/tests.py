from django.test import TestCase
from unittest.mock import patch, MagicMock

from url_process.models import URL
from url_process.url_utils.url_handler import URLHandler


class URLModelTests(TestCase):

    def test_str_representation(self):
        url = URL.objects.create(address="http://example.com")
        self.assertEqual(str(url), "http://example.com")

    def test_update_allow_listed(self):
        url = URL.objects.create(
            address="http://malicious.com",
            ioc_score=7,
            ioc_confidence=20,
            ioc_level="info",
        )

        url.update_allow_listed()
        url.refresh_from_db()

        self.assertEqual(url.ioc_score, 0)
        self.assertEqual(url.ioc_confidence, 100)
        self.assertEqual(url.ioc_level, "SAFE-ALLOW_LISTED")


class URLHandlerTests(TestCase):

    @patch("url_process.url_utils.url_handler.DomainHandler")
    def test_handle_url_detects_domain(self, MockDomainHandler):
        """
        When DomainHandler.validate_domain() returns 'Domain',
        handle_url should return (None, domain_instance).
        """
        mock_domain_handler = MockDomainHandler.return_value
        mock_domain_handler.validate_domain.return_value = "Domain"
        mock_domain_instance = MagicMock()
        mock_domain_handler.handle_domain.return_value = mock_domain_instance

        handler = URLHandler()
        url_instance, domain_instance = handler.handle_url("example.com")

        self.assertIsNone(url_instance)
        self.assertEqual(domain_instance, mock_domain_instance)
        mock_domain_handler.handle_domain.assert_called_once_with("example.com")

    @patch("url_process.url_utils.url_handler.DomainHandler")
    def test_handle_url_invalid_returns_none_none(self, MockDomainHandler):
        MockDomainHandler.return_value.validate_domain.return_value = None

        handler = URLHandler()
        url_instance, domain_instance = handler.handle_url("not a url")
        self.assertIsNone(url_instance)
        self.assertIsNone(domain_instance)

    @patch("url_process.url_utils.url_handler.DomainInIocs")
    @patch("url_process.url_utils.url_handler.Domain")
    @patch("url_process.url_utils.url_handler.DomainHandler")
    def test_create_or_update_url_new_url(
        self,
        MockDomainHandler,
        MockDomain,
        MockDomainInIocs,
    ):
        # Domain validated as a URL type
        mock_domain_handler = MockDomainHandler.return_value
        mock_domain_handler.validate_domain.side_effect = ["Url", "Domain"]

        # Domain model behavior
        mock_domain_instance = MockDomain.objects.get_or_create.return_value = (
            MagicMock(),
            True,
        )

        # DomainInIocs
        mock_di_instance = MagicMock()
        MockDomainInIocs.objects.get_or_create.return_value = (mock_di_instance, True)

        handler = URLHandler()

        url_str = "http://example.com/path"
        url_instance, domain_instance = handler.handle_url(url_str)

        # URL object created
        self.assertIsNotNone(url_instance)
        self.assertEqual(url_instance.address, url_str)

        # Domain extracted
        self.assertIsNotNone(domain_instance)

        MockDomainInIocs.objects.get_or_create.assert_called_once()

    @patch("url_process.url_utils.url_handler.DomainInIocs")
    @patch("url_process.url_utils.url_handler.Domain")
    @patch("url_process.url_utils.url_handler.DomainHandler")
    def test_create_or_update_url_increments_times_sent_on_existing_url(
        self,
        MockDomainHandler,
        MockDomain,
        MockDomainInIocs,
    ):
        # First part: create initial URL
        existing_url = URL.objects.create(address="http://example.com")

        # Mock domain validation
        mock_domain_handler = MockDomainHandler.return_value
        mock_domain_handler.validate_domain.side_effect = ["Url", "Domain"]

        MockDomain.objects.get_or_create.return_value = (MagicMock(), True)
        MockDomainInIocs.objects.get_or_create.return_value = (MagicMock(), True)

        handler = URLHandler()
        handler.handle_url("http://example.com")

        existing_url.refresh_from_db()
        self.assertEqual(existing_url.times_sent, 1)  # incremented

    @patch("url_process.url_utils.url_handler.DomainHandler")
    def test_get_domain_extracts_and_normalizes(self, MockDomainHandler):
        # validate_domain returns Domain to mark it valid
        MockDomainHandler.return_value.validate_domain.return_value = "Domain"

        domain = URLHandler.get_domain("http://www.Example.com/path")
        self.assertEqual(domain, "example.com")

    @patch("url_process.url_utils.url_handler.DomainHandler")
    def test_get_domain_invalid_returns_none(self, MockDomainHandler):
        MockDomainHandler.return_value.validate_domain.return_value = None

        domain = URLHandler.get_domain("http://invalid_domain###")
        self.assertIsNone(domain)


class URLHandlerExceptionTests(TestCase):

    @patch("url_process.url_utils.url_handler.URL.objects.get_or_create")
    def test_create_or_update_url_handles_exception(self, mock_get_or_create):
        """
        If URL.objects.get_or_create raises an exception,
        _create_or_update_url should return (None, None).
        """
        mock_get_or_create.side_effect = Exception("DB error")

        handler = URLHandler()
        url_instance, domain_instance = handler._create_or_update_url("http://bad.com")

        self.assertIsNone(url_instance)
        self.assertIsNone(domain_instance)

    @patch("url_process.url_utils.url_handler.Domain.objects.get_or_create")
    def test_create_or_update_domain_handles_exception(self, mock_domain_get):
        """
        If Domain.objects.get_or_create raises an exception,
        _create_or_update_domain() should return None.
        """
        mock_domain_get.side_effect = Exception("Domain creation failed")

        handler = URLHandler()
        domain_instance = handler._create_or_update_domain("example.com")

        self.assertIsNone(domain_instance)

    @patch("url_process.url_utils.url_handler.urlparse")
    def test_get_domain_exception_returns_none(self, mock_urlparse):
        """
        If urlparse throws an exception, get_domain should return None.
        """
        mock_urlparse.side_effect = Exception("Parsing error")

        domain = URLHandler.get_domain("http://example.com")
        self.assertIsNone(domain)