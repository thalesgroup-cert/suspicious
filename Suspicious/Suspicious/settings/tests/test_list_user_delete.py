from django.contrib.auth.models import User
from django.test import TestCase

from domain_process.models import Domain
from settings.models import AllowListDomain, AllowListFiletype, AllowListIp, DenyListDomain
from ip_process.models import IP


class ListEntriesSurviveUserDeletionTests(TestCase):
    """Deleting an account must not silently delete the allow/deny entries it added."""

    def test_entries_stay_and_lose_their_author(self):
        u = User.objects.create_user("gone", password="p")
        allow = AllowListDomain.objects.create(domain=Domain.objects.create(value="keep.example"), user=u)
        deny = DenyListDomain.objects.create(domain=Domain.objects.create(value="bad.example"), user=u)
        ip = AllowListIp.objects.create(ip=IP.objects.create(address="9.9.9.9"), user=u)
        ft = AllowListFiletype.objects.create(filetype="pdf", user=u)

        u.delete()

        for obj in (allow, deny, ip, ft):
            obj.refresh_from_db()
            self.assertIsNone(obj.user)
