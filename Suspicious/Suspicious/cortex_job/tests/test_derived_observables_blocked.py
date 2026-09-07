from django.contrib.auth import get_user_model
from django.test import TestCase

from cortex_job.cortex_utils.derived_observables import _blocked
from domain_process.models import Domain
from settings.models import AllowListDomain


class BlockedTests(TestCase):
    def test_plain_url_is_allowed(self):
        self.assertEqual(_blocked("https://evil.example/login", "url"), "")

    def test_ssrf_url_is_blocked(self):
        self.assertTrue(_blocked("http://169.254.169.254/latest/meta-data/", "url"))

    def test_allow_listed_domain_is_blocked(self):
        # AllowListDomain.domain is a FK to Domain(value=...); user FK is required.
        user = get_user_model().objects.create_user(username="al_u", password="x")
        domain = Domain.objects.create(value="good.example")
        AllowListDomain.objects.create(domain=domain, user=user)
        self.assertTrue(_blocked("https://good.example/anything", "url"))
        self.assertTrue(_blocked("good.example", "domain"))

    def test_non_url_non_domain_types_are_allowed(self):
        self.assertEqual(_blocked("1.2.3.4", "ip"), "")
        self.assertEqual(_blocked("deadbeef" * 8, "hash"), "")
