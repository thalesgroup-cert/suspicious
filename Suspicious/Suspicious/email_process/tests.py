from django.test import TestCase
from unittest.mock import patch, MagicMock

from email_process.models import MailAddress
from email_process.email_utils.email_handler import (
    MailAddressHandler,
    get_domain,
    is_valid_email,
    is_valid_company_email,
)


class MailAddressModelTests(TestCase):

    def test_str_representation(self):
        m = MailAddress.objects.create(address="user@example.com")
        self.assertEqual(str(m), "user@example.com")

    def test_default_fields(self):
        m = MailAddress.objects.create(address="a@b.com")
        self.assertEqual(m.ioc_score, 5)
        self.assertEqual(m.ioc_confidence, 0)
        self.assertEqual(m.ioc_level, "info")
        self.assertFalse(m.is_internal)


class GetDomainTests(TestCase):

    @patch("email_process.email_utils.email_handler.DomainHandler")
    def test_get_domain_valid_mail(self, MockDH):
        MockDH.return_value.validate_email.return_value = "Mail"
        mail = MailAddress(address="alice@example.com")

        domain = get_domain(mail)
        self.assertEqual(domain, "example.com")

    @patch("email_process.email_utils.email_handler.DomainHandler")
    def test_get_domain_invalid_returns_none(self, MockDH):
        MockDH.return_value.validate_email.return_value = None
        MockDH.return_value.validate_domain.return_value = None

        mail = MailAddress(address="invalid")
        self.assertIsNone(get_domain(mail))

    @patch("email_process.email_utils.email_handler.DomainHandler")
    def test_get_domain_valid_domain(self, MockDH):
        MockDH.return_value.validate_email.return_value = None
        MockDH.return_value.validate_domain.return_value = "Domain"

        mail = MailAddress(address="example.com")
        self.assertEqual(get_domain(mail), "example.com")


class EmailValidationTests(TestCase):

    def test_is_valid_email_valid(self):
        ok, normalized = is_valid_email("A.LICE+tag@Example.com")
        self.assertTrue(ok)
        self.assertEqual(normalized, "a.lice+tag@example.com")

    def test_is_valid_email_invalid(self):
        ok, msg = is_valid_email("bad@@example..com")
        self.assertFalse(ok)
        self.assertIsInstance(msg, str)


class CompanyEmailTests(TestCase):

    @patch("email_process.email_utils.email_handler.company_config", ["example.com"])
    @patch("email_process.email_utils.email_handler.validate_email")
    def test_is_valid_company_email_true(self, mock_validate):
        mock_validate.return_value = MagicMock(email="alice@example.com")
        self.assertTrue(is_valid_company_email("alice@example.com"))

    @patch("email_process.email_utils.email_handler.company_config", ["example.com"])
    def test_is_valid_company_email_false(self):
        self.assertFalse(is_valid_company_email("bob@other.com"))

    @patch("email_process.email_utils.email_handler.company_config", ["example.com"])
    def test_is_valid_company_email_invalid(self):
        self.assertFalse(is_valid_company_email("not-an-email"))


class MailAddressHandlerTests(TestCase):

    @patch("email_process.email_utils.email_handler.DomainInIocs")
    @patch("email_process.email_utils.email_handler._create_or_update_domain")
    @patch("email_process.email_utils.email_handler.get_domain")
    @patch("email_process.email_utils.email_handler.is_valid_company_email")
    @patch("email_process.email_utils.email_handler.is_valid_email")
    def test_handle_mail_creates_new_internal(
        self,
        mock_is_valid_email,
        mock_is_valid_company_email,
        mock_get_domain,
        mock_create_domain,
        MockDomainInIocs,
    ):
        mock_is_valid_email.return_value = (True, "alice@example.com")
        mock_is_valid_company_email.return_value = True
        mock_get_domain.return_value = "example.com"
        mock_domain_instance = MagicMock()
        mock_create_domain.return_value = mock_domain_instance

        mock_di = MagicMock()
        MockDomainInIocs.objects.get_or_create.return_value = (mock_di, True)

        handler = MailAddressHandler()
        m = handler.handle_mail("alice@example.com")

        self.assertIsNotNone(m)
        self.assertTrue(m.is_internal)

    @patch("email_process.email_utils.email_handler.DomainInIocs")
    @patch("email_process.email_utils.email_handler._create_or_update_domain")
    @patch("email_process.email_utils.email_handler.get_domain")
    @patch("email_process.email_utils.email_handler.is_valid_company_email")
    @patch("email_process.email_utils.email_handler.is_valid_email")
    def test_handle_mail_existing_not_increment_is_internal(
        self,
        mock_is_valid_email,
        mock_is_valid_company_email,
        mock_get_domain,
        mock_create_domain,
        MockDomainInIocs,
    ):
        existing = MailAddress.objects.create(address="bob@example.com")

        mock_is_valid_email.return_value = (True, "bob@example.com")
        mock_is_valid_company_email.return_value = False
        mock_get_domain.return_value = "example.com"
        mock_create_domain.return_value = MagicMock()
        MockDomainInIocs.objects.get_or_create.return_value = (MagicMock(), True)

        handler = MailAddressHandler()
        m = handler.handle_mail("bob@example.com")

        self.assertEqual(m.id, existing.id)
        self.assertFalse(m.is_internal)

    @patch("email_process.email_utils.email_handler.MailAddress.objects.get_or_create")
    def test_handle_mail_exception_returns_none(self, mock_get):
        mock_get.side_effect = Exception("DB error")

        handler = MailAddressHandler()
        result = handler.handle_mail("foo@example.com")

        self.assertIsNone(result)
