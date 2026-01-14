from django.test import TestCase
from unittest.mock import patch, MagicMock

from domain_process.models import Domain
from domain_process.domain_utils.domain_handler import DomainHandler, normalize_domain
from url_process.models import URL
from email_process.models import MailAddress


class DomainModelTests(TestCase):
    def test_str_representation(self):
        domain = Domain.objects.create(value="example.com")
        self.assertEqual(str(domain), "example.com")

    def test_linked_url_relationship(self):
        domain = Domain.objects.create(value="linked.com")
        url = URL.objects.create(address="http://linked.com/path")
        domain.linked_urls.add(url)

        self.assertIn(url, domain.linked_urls.all())
        self.assertIn(domain, url.domains.all())

    def test_linked_mail_relationship(self):
        domain = Domain.objects.create(value="maildomain.com")
        mail = MailAddress.objects.create(address="user@maildomain.com")
        domain.linked_mail_addresses.add(mail)

        self.assertIn(mail, domain.linked_mail_addresses.all())
        self.assertIn(domain, mail.domains.all())


class NormalizeDomainTests(TestCase):
    def test_normalize_valid_subdomain(self):
        result = normalize_domain("www.test.example.co.uk")
        self.assertEqual(result, "example.co.uk")

    def test_normalize_invalid(self):
        self.assertIsNone(normalize_domain("not a domain"))


class DomainHandlerValidateTests(TestCase):
    def setUp(self):
        self.handler = DomainHandler()

    def test_validate_domain_empty(self):
        self.assertEqual(self.handler.validate_domain(""), "Invalid Domain")

    def test_validate_domain_plain(self):
        self.assertEqual(self.handler.validate_domain("example.org"), "Domain")

    def test_validate_url(self):
        self.assertEqual(self.handler.validate_domain("http://example.org"), "Url")


class DomainHandlerTests(TestCase):

    @patch("domain_process.domain_utils.domain_handler.normalize_domain")
    def test_validate_email_success(self, mock_normalize):
        handler = DomainHandler()
        self.assertEqual(handler.validate_email("user@example.com"), "Mail")

    @patch("domain_process.domain_utils.domain_handler.normalize_domain")
    def test_handle_domain_creates_new(self, mock_normalize):
        mock_normalize.return_value = "new.com"

        handler = DomainHandler()
        instance = handler.handle_domain("new.com")

        self.assertIsNotNone(instance)
        self.assertEqual(instance.value, "new.com")
        mock_normalize.assert_called_once_with("new.com")

    @patch("domain_process.domain_utils.domain_handler.normalize_domain")
    def test_handle_domain_none_on_invalid(self, mock_normalize):
        mock_normalize.return_value = None

        handler = DomainHandler()
        result = handler.handle_domain("!notvalid!")

        self.assertIsNone(result)
        mock_normalize.assert_called_once_with("!notvalid!")

    @patch("domain_process.domain_utils.domain_handler.normalize_domain")
    def test_handle_existing_domain_updates_timestamp(self, mock_normalize):
        mock_normalize.return_value = "duplicate.com"
        existing = Domain.objects.create(value="duplicate.com")

        old_time = existing.last_update

        handler = DomainHandler()
        handler.handle_domain("duplicate.com")

        existing.refresh_from_db()
        self.assertGreater(existing.last_update, old_time)
        mock_normalize.assert_called_once()

    # 🧩 Fixture-like test for complex normalization logic
    # You can adjust rules here for more edge cases
    @patch("domain_process.domain_utils.domain_handler.normalize_domain")
    def test_handle_complex_normalization_rules(self, mock_normalize):
        # Suppose a rule that strips uppercase and special chars
        mock_normalize.side_effect = lambda d: d.lower().replace("!", "")
        handler = DomainHandler()

        instance = handler.handle_domain("Example!DOMAIN.com")
        self.assertEqual(instance.value, "exampledomain.com")


class DomainHandlerExceptionTests(TestCase):

    @patch("domain_process.domain_utils.domain_handler.Domain.objects.get_or_create")
    def test_handle_domain_exception_returns_none(self, mock_get):
        mock_get.side_effect = Exception("DB failure")

        handler = DomainHandler()
        result = handler.handle_domain("example.com")

        self.assertIsNone(result)

    @patch("domain_process.domain_utils.domain_handler.normalize_domain")
    def test_normalize_exception_is_caught_and_returns_none(self, mock_normalize):
        # Make normalize_domain raise Exception
        mock_normalize.side_effect = Exception("unexpected error")

        handler = DomainHandler()
        result = handler.handle_domain("badinput")

        # Because handler catches any exception inside handle_domain
        self.assertIsNone(result)

