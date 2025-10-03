from django.test import TestCase
from django.utils import timezone
from domain_process.models import Domain, DomainInIocs
from url_process.models import URL
from email_process.models import MailAddress


class DomainModelTest(TestCase):
    def setUp(self):
        self.domain = Domain.objects.create(
            value="example.com",
            ioc_score=7.0,
            ioc_confidence=90,
            ioc_level="high",
            category="phishing"
        )

    def test_domain_creation(self):
        self.assertEqual(self.domain.value, "example.com")
        self.assertEqual(self.domain.ioc_score, 7.0)
        self.assertEqual(self.domain.ioc_confidence, 90)
        self.assertEqual(self.domain.ioc_level, "high")
        self.assertEqual(self.domain.category, "phishing")
        self.assertIsNotNone(self.domain.creation_date)
        self.assertIsNotNone(self.domain.last_update)
        self.assertEqual(str(self.domain), "example.com")

    def test_domain_default_values(self):
        domain = Domain.objects.create(value="test.org")
        self.assertEqual(domain.ioc_score, 5)
        self.assertEqual(domain.ioc_confidence, 0)
        self.assertEqual(domain.ioc_level, "info")
        self.assertEqual(domain.category, "unknown category")
        self.assertEqual(domain.times_sent, 0)


class DomainInIocsModelTest(TestCase):
    def setUp(self):
        self.domain = Domain.objects.create(value="example.org")
        self.url = URL.objects.create(address="http://example.org/path")
        self.mail = MailAddress.objects.create(address="user@example.org")

    def test_link_domain_to_url(self):
        link = DomainInIocs.objects.create(domain=self.domain, url=self.url)
        self.assertEqual(link.domain, self.domain)
        self.assertEqual(link.url, self.url)
        self.assertIsNone(link.mail_address)
        self.assertEqual(str(link), f"{self.domain.value} - {self.url.address}")

    def test_link_domain_to_mail(self):
        link = DomainInIocs.objects.create(domain=self.domain, mail_address=self.mail)
        self.assertEqual(link.domain, self.domain)
        self.assertEqual(link.mail_address, self.mail)
        self.assertIsNone(link.url)
        self.assertEqual(str(link), f"{self.domain.value} - {self.mail.address}")

    def test_link_domain_alone(self):
        link = DomainInIocs.objects.create(domain=self.domain)
        self.assertIsNone(link.url)
        self.assertIsNone(link.mail_address)
        self.assertEqual(str(link), self.domain.value)
