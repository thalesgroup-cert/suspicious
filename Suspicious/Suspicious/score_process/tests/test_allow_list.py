from django.test import TestCase
from django.contrib.auth.models import User
from ip_process.models import IP
from domain_process.models import Domain
from settings.models import AllowListDomain, AllowListIp, CampaignDomainAllowList, DenyListDomain
from score_process.scoring.cortex_analyzers.allow_list import check_allow_list


class AllowListIpBranchTests(TestCase):
    def test_listed_ip_triggers(self):
        u = User.objects.create_user("u", password="p")
        AllowListIp.objects.create(ip=IP.objects.create(address="8.8.8.8"), user=u)
        result = check_allow_list("8.8.8.8", "ip")
        self.assertEqual(result.IpAllowList, "Safe IPW triggered")

    def test_unlisted_ip_does_not_trigger(self):
        result = check_allow_list("1.2.3.4", "ip")
        self.assertIsNone(result.IpAllowList)

    def test_non_normalised_ip_matches_stored(self):
        u = User.objects.create_user("u2", password="p")
        AllowListIp.objects.create(ip=IP.objects.create(address="::1"), user=u)
        result = check_allow_list("0:0:0:0:0:0:0:1", "ip")
        self.assertEqual(result.IpAllowList, "Safe IPW triggered")

    def test_unparseable_ip_does_not_crash(self):
        result = check_allow_list("garbage", "ip")
        self.assertIsNone(result.IpAllowList)


class AllowListOverrideTests(TestCase):
    def setUp(self):
        self.u = User.objects.create_user("ov", password="p")
        self.d = Domain.objects.create(value="both.example")
        AllowListDomain.objects.create(domain=self.d, user=self.u)

    def test_allow_listed_domain_triggers(self):
        self.assertEqual(check_allow_list("both.example", "domain").DomainAllowList, "Safe DW triggered")

    def test_campaign_domain_never_triggers_for_domain_or_url(self):
        CampaignDomainAllowList.objects.create(domain=self.d, user=self.u)
        self.assertIsNone(check_allow_list("both.example", "domain").DomainAllowList)
        self.assertIsNone(check_allow_list("https://both.example/x", "url").DomainAllowList)


class AllowListWwwHostTests(TestCase):
    """Allow-listing example.com must cover www.example.com URLs.

    Regression: the scoring path compared the raw host, so only the bare domain
    matched. A URL on www.<listed domain> kept its analyzer scores, counted as a
    finding on an unlisted target, and a clean internal mail ended up Dangerous.
    """

    def setUp(self):
        self.u = User.objects.create_user("www", password="p")
        self.d = Domain.objects.create(value="corp.example")
        AllowListDomain.objects.create(domain=self.d, user=self.u)

    def test_www_and_path_urls_match_the_bare_listed_domain(self):
        for url in ("http://corp.example", "http://www.corp.example", "https://www.corp.example/en"):
            with self.subTest(url):
                self.assertEqual(check_allow_list(url, "url").DomainAllowList, "Safe DW triggered")

    def test_other_subdomains_are_not_covered(self):
        self.assertIsNone(check_allow_list("https://evil.corp.example/x", "url").DomainAllowList)

    def test_entry_stored_with_www_still_matches(self):
        www = Domain.objects.create(value="www.other.example")
        AllowListDomain.objects.create(domain=www, user=self.u)
        self.assertEqual(check_allow_list("https://www.other.example/", "url").DomainAllowList, "Safe DW triggered")

    def test_deny_listed_bare_domain_still_overrides_for_www_urls(self):
        DenyListDomain.objects.create(domain=self.d, user=self.u)
        self.assertIsNone(check_allow_list("https://www.corp.example/", "url").DomainAllowList)
