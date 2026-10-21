from django.contrib.auth import get_user_model
from django.test import TestCase

from domain_process.models import Domain
from ip_process.models import IP
from settings.allow_lists import is_ip_allow_listed, normalise_ip, overrides_allow_list
from settings.models import AllowListIp, CampaignDomainAllowList, DenyListDomain, WatcherMonitoredDomain


class AllowListHelpersTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="al_u", password="x")

    def test_normalise_ip(self):
        self.assertEqual(normalise_ip(" 2606:4700:4700:0:0:0:0:1111 "), "2606:4700:4700::1111")
        self.assertEqual((normalise_ip(" garbage "), normalise_ip(None)), ("garbage", ""))

    def test_ip_match_ignores_spelling(self):
        AllowListIp.objects.create(ip=IP.objects.create(address="2606:4700:4700::1111"), user=self.user)
        self.assertTrue(is_ip_allow_listed("2606:4700:4700:0:0:0:0:1111"))
        self.assertFalse(is_ip_allow_listed("8.8.4.4"))

    def test_overrides_allow_list(self):
        self.assertFalse(overrides_allow_list(None))
        self.assertFalse(overrides_allow_list(Domain.objects.create(value="plain.test")))
        deny, mon, camp = (Domain.objects.create(value=v) for v in ("deny.test", "mon.test", "camp.test"))
        DenyListDomain.objects.create(domain=deny, user=self.user)
        WatcherMonitoredDomain.objects.create(domain=mon)
        CampaignDomainAllowList.objects.create(domain=camp, user=self.user)
        for d in (deny, mon, camp):
            self.assertTrue(overrides_allow_list(d), d.value)
