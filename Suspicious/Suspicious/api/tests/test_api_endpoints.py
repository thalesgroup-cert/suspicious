"""Per-app endpoint smoke tests — auth required, happy path, validation.

Mirrors the per-feature shape of the frontend suites: each app gets a
small block covering (a) auth is enforced, (b) the happy path returns the
expected status, (c) obvious validation errors are rejected.
"""
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

User = get_user_model()


class AuthEndpointTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(username="auth_user", password="pw-12345")

    def test_login_rejects_bad_credentials(self):
        resp = self.client.post(
            reverse("login"),
            {"username": "auth_user", "password": "wrong"},
            format="json",
        )
        self.assertEqual(resp.status_code, 400)

    def test_me_requires_auth(self):
        resp = self.client.get(reverse("me"))
        self.assertIn(resp.status_code, (401, 403))

    def test_me_returns_identity_for_authenticated_user(self):
        self.client.force_authenticate(self.user)
        resp = self.client.get(reverse("me"))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["username"], "auth_user")
        self.assertIn("groups", resp.data)


class ProfileEndpointTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(username="profile_user", password="pw-12345")

    def test_profile_requires_auth(self):
        resp = self.client.get(reverse("profile"))
        self.assertIn(resp.status_code, (401, 403))

    def test_get_profile_autocreates_and_returns_200(self):
        self.client.force_authenticate(self.user)
        resp = self.client.get(reverse("profile"))
        self.assertEqual(resp.status_code, 200)
        self.assertIn("theme", resp.data)

    def test_patch_preferences_updates_flag(self):
        self.client.force_authenticate(self.user)
        resp = self.client.patch(
            reverse("profile-preferences"),
            {"wants_results": False},
            format="json",
        )
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.data["wants_results"])

    def test_patch_appearance_rejects_invalid_theme(self):
        self.client.force_authenticate(self.user)
        resp = self.client.patch(
            reverse("profile-appearance"),
            {"theme": "definitely-not-a-theme"},
            format="json",
        )
        self.assertEqual(resp.status_code, 400)


class DashboardEndpointTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(username="dash_user", password="pw-12345")

    def test_summary_requires_auth(self):
        resp = self.client.get(reverse("dashboard-summary"))
        self.assertIn(resp.status_code, (401, 403))

    def test_summary_requires_month_and_year(self):
        self.client.force_authenticate(self.user)
        resp = self.client.get(reverse("dashboard-summary"))
        self.assertEqual(resp.status_code, 400)

    def test_summary_returns_payload_with_params(self):
        self.client.force_authenticate(self.user)
        resp = self.client.get(reverse("dashboard-summary"), {"month": 5, "year": 2026})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("kpis", resp.data)
        self.assertIn("danger_counts", resp.data)
