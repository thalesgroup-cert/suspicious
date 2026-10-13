"""Dashboard scope resolution (api/permissions/dashboard_scope.py) and the
summary/scopes endpoints."""
from django.contrib.auth.models import Group, User
from django.core.cache import cache
from rest_framework.exceptions import PermissionDenied
from rest_framework.test import APITestCase

from api.permissions.dashboard_scope import resolve_scope
from dashboard.tests_regional import seed
from profiles.models import CISOProfile, UserProfile

SUMMARY = "/api/dashboard/summary/"
SCOPES = "/api/dashboard/scopes/"


def profile(user, country, region):
    UserProfile.objects.create(user=user, function="", gbu="Off GBU", country=country, region=region)


def in_group(user, name):
    user.groups.add(Group.objects.get_or_create(name=name)[0])


class DashboardScopeTests(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.au1, cls.au2, cls.nz1, cls.us1 = seed()
        profile(cls.au1, "AU", "APAC")
        profile(cls.nz1, "NZ", "APAC")
        profile(cls.us1, "US", "NORAM")
        cls.nobody = User.objects.create_user("nobody@meridian.example", password="x")
        cls.cert = User.objects.create_user("cert@meridian.example", password="x")
        in_group(cls.cert, "CERT")
        cls.ciso = User.objects.create_user("ciso@meridian.example", password="x")
        in_group(cls.ciso, "CISO")
        CISOProfile.objects.create(
            user=cls.ciso, function="", gbu="Off GBU", country="AU", region="APAC", scope="AU|Off GBU"
        )

    def setUp(self):
        cache.clear()

    def _get(self, user, url, **params):
        self.client.force_authenticate(user)
        return self.client.get(url, {"month": 10, "year": 2026, **params})

    # resolve_scope

    def test_plain_user_defaults_to_own_country(self):
        scope = resolve_scope(self.au1, None)
        self.assertEqual(scope.key, "OWN_COUNTRY")
        self.assertEqual(scope.groups, ["AU"])

    def test_plain_user_may_pick_overall(self):
        self.assertIsNone(resolve_scope(self.au1, "ALL").groups)

    def test_plain_user_cannot_pick_another_country(self):
        for requested in ("COUNTRY:NZ", "REGION:APAC", "OWN_SCOPE", "bogus"):
            with self.assertRaises(PermissionDenied, msg=requested):
                resolve_scope(self.au1, requested)

    def test_user_without_profile_gets_overall_only(self):
        self.assertEqual(resolve_scope(self.nobody, None).key, "ALL")
        with self.assertRaises(PermissionDenied):
            resolve_scope(self.nobody, "OWN_COUNTRY")

    def test_ciso_resolves_to_profile_scope(self):
        scope = resolve_scope(self.ciso, None)
        self.assertEqual(scope.key, "OWN_SCOPE")
        self.assertEqual(scope.groups, ["AU", "Off GBU"])
        self.assertIsNone(resolve_scope(self.ciso, "ALL").groups)
        with self.assertRaises(PermissionDenied):
            resolve_scope(self.ciso, "COUNTRY:NZ")

    def test_cert_may_pick_any_scope(self):
        self.assertEqual(resolve_scope(self.cert, "COUNTRY:NZ").groups, ["NZ"])
        self.assertEqual(resolve_scope(self.cert, "REGION:NORAM").groups, ["NORAM"])
        self.assertIsNone(resolve_scope(self.cert, None).groups)

    # summary endpoint

    def test_summary_plain_user_default_is_own_country(self):
        data = self._get(self.au1, SUMMARY).data
        self.assertEqual(data["scope"]["key"], "OWN_COUNTRY")
        self.assertEqual(data["reports"], 6)
        self.assertEqual(data["outcomes"]["dangerous"], 1)
        self.assertIsNone(data["top_reporters"])
        # Legacy keys stay populated for the current UI, without names.
        self.assertEqual(data["kpis"]["total_cases"], 6)
        self.assertEqual(data["kpis"]["total_reporters"], 2)
        self.assertEqual(data["danger_counts"]["dangerous"], 1)
        self.assertEqual(data["danger_counts"]["malicious"], 1)
        self.assertEqual(data["top_prefixes"], [])

    def test_summary_plain_user_overall(self):
        data = self._get(self.au1, SUMMARY, scope="ALL").data
        self.assertEqual(data["scope"], {"key": "ALL", "label": "Overall"})
        self.assertEqual(data["reports"], 8)
        self.assertIsNone(data["top_reporters"])

    def test_summary_plain_user_other_country_is_403(self):
        resp = self._get(self.au1, SUMMARY, scope="COUNTRY:NZ")
        self.assertEqual(resp.status_code, 403)
        self.assertNotIn("reports", resp.data)

    def test_summary_cert_sees_names(self):
        data = self._get(self.cert, SUMMARY, scope="COUNTRY:AU").data
        self.assertEqual(data["top_reporters"][0], {"label": "au1", "value": 4})
        self.assertEqual(data["top_prefixes"], data["top_reporters"])

    def test_summary_ciso_scope_and_names(self):
        data = self._get(self.ciso, SUMMARY).data
        self.assertEqual(data["scope"]["key"], "OWN_SCOPE")
        self.assertEqual(data["reports"], 4)
        self.assertEqual(data["top_reporters"], [{"label": "au1", "value": 4}])

    # scopes endpoint

    def test_scopes_plain_user(self):
        data = self._get(self.au1, SCOPES).data
        self.assertEqual(data["default"], "OWN_COUNTRY")
        self.assertEqual([o["key"] for o in data["options"]], ["OWN_COUNTRY", "ALL"])

    def test_scopes_user_without_country(self):
        data = self._get(self.nobody, SCOPES).data
        self.assertEqual(data, {"default": "ALL", "options": [{"key": "ALL", "label": "Overall"}]})

    def test_scopes_ciso(self):
        data = self._get(self.ciso, SCOPES).data
        self.assertEqual(data["default"], "OWN_SCOPE")
        self.assertIn({"key": "OWN_SCOPE", "label": "AU | Off GBU"}, data["options"])
        self.assertNotIn("COUNTRY:NZ", [o["key"] for o in data["options"]])

    def test_scopes_cert_lists_profile_countries_and_regions(self):
        keys = [o["key"] for o in self._get(self.cert, SCOPES).data["options"]]
        for key in ("ALL", "COUNTRY:AU", "COUNTRY:NZ", "COUNTRY:US", "REGION:APAC", "REGION:NORAM"):
            self.assertIn(key, keys)
        self.assertEqual(len(keys), len(set(keys)))
