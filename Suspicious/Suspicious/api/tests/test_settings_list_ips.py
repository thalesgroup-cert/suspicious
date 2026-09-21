"""Tests for the ips_allow settings list section (AllowListIp management)."""
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from settings.models import AllowListIp

User = get_user_model()


class IpsAllowSectionTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("u", password="p")
        self.user.groups.add(Group.objects.get_or_create(name="Admin")[0])
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    def _list_url(self):
        return reverse("settings-list", kwargs={"section": "ips_allow"})

    def test_post_creates_entries(self):
        r = self.client.post(self._list_url(), {"values": ["8.8.8.8", "1.1.1.1"]}, format="json")
        self.assertEqual(r.status_code, 201)
        self.assertEqual(AllowListIp.objects.count(), 2)

    def test_get_lists_entries(self):
        self.client.post(self._list_url(), {"values": ["9.9.9.9"]}, format="json")
        r = self.client.get(self._list_url())
        self.assertEqual(r.status_code, 200)
        rows = r.json()["results"]
        self.assertIn("9.9.9.9", [x["value"] for x in rows])

    def test_duplicate_reported_not_double_created(self):
        self.client.post(self._list_url(), {"values": ["8.8.8.8"]}, format="json")
        r = self.client.post(self._list_url(), {"values": ["8.8.8.8"]}, format="json")
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.json()["duplicates"], ["8.8.8.8"])
        self.assertEqual(r.json()["created"], [])
        self.assertEqual(AllowListIp.objects.count(), 1)

    def test_invalid_ip_rejected_whole_batch(self):
        # "not-an-ip" is garbage; "192.168.001.1" is a leading-zero octal
        # ambiguity that stdlib ipaddress rejects (CVE-2021-29921). Either
        # one rejects the entire batch — nothing is created.
        r = self.client.post(
            self._list_url(),
            {"values": ["10.0.0.1", "not-an-ip", "192.168.001.1"]},
            format="json",
        )
        self.assertEqual(r.status_code, 400)
        self.assertEqual(AllowListIp.objects.count(), 0)

    def test_ipv6_normalised_on_create(self):
        r = self.client.post(
            self._list_url(),
            {"values": ["0:0:0:0:0:0:0:1"]},
            format="json",
        )
        self.assertEqual(r.status_code, 201)
        self.assertEqual(AllowListIp.objects.get().ip.address, "::1")

    def test_valid_cidr_string_rejected(self):
        # ip_address() does not accept networks — "10.0.0.0/8" is not a host IP
        r = self.client.post(self._list_url(), {"values": ["10.0.0.0/8"]}, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(AllowListIp.objects.count(), 0)

    def test_delete_removes_entry(self):
        self.client.post(self._list_url(), {"values": ["8.8.8.8"]}, format="json")
        obj = AllowListIp.objects.get()
        r = self.client.delete(
            reverse("settings-list-delete", kwargs={"section": "ips_allow", "item_id": obj.id})
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(AllowListIp.objects.count(), 0)
