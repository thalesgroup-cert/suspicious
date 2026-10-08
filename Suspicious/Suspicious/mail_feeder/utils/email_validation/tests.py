from django.test import SimpleTestCase

from .models import ConfigModel
from .validators import EmailValidatorService


def _service(company=("partner.example",), own=()):
    return EmailValidatorService(ConfigModel(company_domains=list(company), own_domains=list(own)))


class OwnDomainTests(SimpleTestCase):
    def test_listed_domain_matches_exactly_as_before(self):
        self.assertTrue(_service().is_company_email("a@partner.example").is_valid)

    def test_subdomain_of_a_listed_domain_is_not_trusted(self):
        self.assertFalse(_service().is_company_email("a@evil.partner.example").is_valid)

    def test_own_domain_and_its_subdomains_are_company(self):
        s = _service(own=("corp.example",))
        for addr in ("a@corp.example", "a@uk.corp.example", "a@deep.sub.corp.example", "A@UK.Corp.Example"):
            self.assertTrue(s.is_company_email(addr).is_valid, addr)

    def test_lookalikes_of_the_own_domain_are_not_company(self):
        s = _service(own=("corp.example",))
        for addr in ("a@evilcorp.example", "a@corp.example.evil.io", "a@corp-example.com", "a@xcorp.example"):
            self.assertFalse(s.is_company_email(addr).is_valid, addr)

    def test_no_own_domains_changes_nothing(self):
        self.assertFalse(_service().is_company_email("a@uk.corp.example").is_valid)
