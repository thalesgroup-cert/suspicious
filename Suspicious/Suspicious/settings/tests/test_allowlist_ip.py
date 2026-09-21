from django.test import TestCase
from django.contrib.auth.models import User
from ip_process.models import IP
from settings.models import AllowListIp


class AllowListIpModelTests(TestCase):
    def test_create_links_ip(self):
        u = User.objects.create_user("u", password="p")
        ip = IP.objects.create(address="8.8.8.8")
        entry = AllowListIp.objects.create(ip=ip, user=u)
        self.assertEqual(str(entry), "8.8.8.8")
