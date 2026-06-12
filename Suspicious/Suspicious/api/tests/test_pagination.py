"""Pagination regression tests for the settings list endpoints.

Allow/deny and analyzer lists must return the bounded, paginated shape
({count, next, previous, results}) rather than an unbounded bare array.
"""
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from cortex_job.models import Analyzer

User = get_user_model()


def _cert_user(username="pg_cert"):
    user = User.objects.create_user(username=username, password="pw-12345")
    group, _ = Group.objects.get_or_create(name="CERT")
    user.groups.add(group)
    return user


class SettingsPaginationTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.cert = _cert_user()
        for i in range(3):
            Analyzer.objects.create(name=f"A{i}", analyzer_cortex_id=f"cx{i}", weight=0.2)

    def test_analyzers_list_is_paginated(self):
        self.client.force_authenticate(self.cert)
        resp = self.client.get(reverse("settings-analyzers"))
        self.assertEqual(resp.status_code, 200)
        for key in ("count", "next", "previous", "results"):
            self.assertIn(key, resp.data)
        self.assertEqual(resp.data["count"], 3)
        self.assertEqual(len(resp.data["results"]), 3)

    def test_analyzers_respect_page_size(self):
        self.client.force_authenticate(self.cert)
        resp = self.client.get(reverse("settings-analyzers"), {"page_size": 1})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.data["results"]), 1)
        self.assertIsNotNone(resp.data["next"])

    def test_settings_list_returns_paginated_shape(self):
        self.client.force_authenticate(self.cert)
        resp = self.client.get(reverse("settings-list", kwargs={"section": "domains_allow"}))
        self.assertEqual(resp.status_code, 200)
        for key in ("count", "next", "previous", "results"):
            self.assertIn(key, resp.data)

    def test_settings_list_requires_elevated_role(self):
        plain = User.objects.create_user("pg_plain", password="pw-12345")
        self.client.force_authenticate(plain)
        resp = self.client.get(reverse("settings-list", kwargs={"section": "domains_allow"}))
        self.assertEqual(resp.status_code, 403)
