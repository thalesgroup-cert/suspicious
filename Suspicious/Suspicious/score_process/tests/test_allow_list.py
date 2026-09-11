from django.test import TestCase
from django.contrib.auth.models import User
from ip_process.models import IP
from settings.models import AllowListIp
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
