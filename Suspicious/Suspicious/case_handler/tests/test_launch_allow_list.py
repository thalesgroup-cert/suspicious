from unittest.mock import MagicMock

from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase

from case_handler.case_utils.case_handler import CaseHandler
from domain_process.models import Domain
from ip_process.models import IP
from settings.models import AllowListDomain, AllowListIp, CampaignDomainAllowList, DenyListDomain


class WebLaunchAllowListTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="web_al", password="x")

    def _handler(self, **filled):
        request = RequestFactory().post("/api/submit")
        request.user = self.user

        def form(key):
            f = MagicMock(**{"is_valid.return_value": key in filled})
            f.cleaned_data = {key: filled[key]} if key in filled else {}
            return f
        return CaseHandler(request, form("file"), form("url"), form("other"))

    def test_allow_listed_ip_gets_reason_and_no_job_unlisted_ip_launches(self):
        AllowListIp.objects.create(ip=IP.objects.create(address="2606:4700:4700::1111"), user=self.user)
        h = self._handler(other="2606:4700:4700:0:0:0:0:1111")
        res = h.validate_forms()
        self.assertTrue(res["allow_listed"])
        self.assertIn("allow-listed", res["allow_reason"])
        self.assertEqual(res["ip_instance"].ioc_level, "SAFE-ALLOW_LISTED")
        self.assertEqual(h.pending_dispatch_intents, [])
        h = self._handler(other="8.8.4.4")
        res = h.validate_forms()
        self.assertFalse(res["allow_listed"])
        self.assertEqual(h.pending_dispatch_intents, [(res["ip_instance"], "ip")])

    def test_allow_listed_url_domain_is_skipped_unless_deny_or_campaign(self):
        for value, model in (("allowed-test.com", None), ("denied-test.com", DenyListDomain),
                             ("sim-test.com", CampaignDomainAllowList)):
            d = Domain.objects.create(value=value)
            AllowListDomain.objects.create(domain=d, user=self.user)
            if model:
                model.objects.create(domain=d, user=self.user)
            h = self._handler(url=f"https://{value}/x")
            res = h.validate_forms()
            self.assertEqual(res["allow_listed"], model is None, value)
            self.assertEqual(len(h.pending_dispatch_intents), 0 if model is None else 1, value)
