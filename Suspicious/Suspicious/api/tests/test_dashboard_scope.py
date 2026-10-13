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
        # Legacy keys the old UI read are gone.
        for key in ("kpis", "danger_counts", "top_prefixes", "malicious"):
            self.assertNotIn(key, data)

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


class DashboardScopeHardeningTests(APITestCase):
    """Fix round 1: authorization hardening."""

    @classmethod
    def setUpTestData(cls):
        cls.au1, cls.au2, cls.nz1, cls.us1 = seed()
        profile(cls.au1, "AU", "APAC")
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

    # C1: country/region/gbu come from LDAP, never from the client.

    def test_plain_user_cannot_patch_country(self):
        self.client.force_authenticate(self.au1)
        self.client.patch("/api/profile/", {"country": "NZ", "region": "NORAM", "gbu": "X"}, format="json")
        p = UserProfile.objects.get(user=self.au1)
        self.assertEqual((p.country, p.region, p.gbu), ("AU", "APAC", "Off GBU"))
        self.assertEqual(self._get(self.au1, SUMMARY, scope="COUNTRY:NZ").status_code, 403)
        self.assertEqual(resolve_scope(self.au1, "OWN_COUNTRY").groups, ["AU"])

    def test_profile_country_without_matching_group_is_ignored(self):
        user = User.objects.create_user("stale@meridian.example", password="x")
        profile(user, "AU", "APAC")  # profile says AU, but no AU group
        data = self._get(user, SCOPES).data
        self.assertEqual(data, {"default": "ALL", "options": [{"key": "ALL", "label": "Overall"}]})
        with self.assertRaises(PermissionDenied):
            resolve_scope(user, "OWN_COUNTRY")

    def test_ciso_cannot_widen_scope_by_patching_country(self):
        self.client.force_authenticate(self.ciso)
        resp = self.client.patch("/api/profile/", {"country": "NZ", "scope": "NZ"}, format="json")
        self.assertEqual(resp.status_code, 400)
        self.client.patch("/api/profile/", {"country": "NZ"}, format="json")
        p = CISOProfile.objects.get(user=self.ciso)
        self.assertEqual((p.country, p.scope), ("AU", "AU|Off GBU"))

    # I-2: CISO names only inside their own scope.

    def test_ciso_overall_has_no_names(self):
        data = self._get(self.ciso, SUMMARY, scope="ALL").data
        self.assertIsNone(data["top_reporters"])
        self.assertIsNotNone(self._get(self.ciso, SUMMARY, scope="OWN_SCOPE").data["top_reporters"])

    # I-3: the cache never hands names to a plain user.

    def test_cached_names_not_served_to_plain_user(self):
        self.assertIsNotNone(self._get(self.cert, SUMMARY, scope="COUNTRY:AU").data["top_reporters"])
        data = self._get(self.au1, SUMMARY, scope="OWN_COUNTRY").data
        self.assertIsNone(data["top_reporters"])

    # The legacy top-prefixes ranking endpoint is removed (the UI reads summary.top_reporters).

    def test_top_prefixes_endpoint_is_gone(self):
        self.client.force_authenticate(self.cert)
        resp = self.client.get("/api/stats/top-prefixes/", {"month": 10, "year": 2026})
        self.assertEqual(resp.status_code, 404)

    # M-5: cache keys never collide.

    def test_cache_key_does_not_collide(self):
        from api.views.dashboard import summary_cache_key

        self.assertNotEqual(
            summary_cache_key(10, 2026, ["A|B"], False), summary_cache_key(10, 2026, ["A", "B"], False)
        )
        self.assertNotEqual(
            summary_cache_key(10, 2026, ["A,B"], False), summary_cache_key(10, 2026, ["A", "B"], False)
        )

    # M-6 / M-9: input validation.

    def test_year_out_of_range_is_400(self):
        self.assertEqual(self._get(self.au1, SUMMARY, year=1).status_code, 400)

    def test_blank_scope_is_400(self):
        self.assertEqual(self._get(self.au1, SUMMARY, scope="").status_code, 400)

    def test_malformed_scopes_are_403(self):
        for requested in ("COUNTRY:", "COUNTRY:AU|NZ", "all", " COUNTRY:NZ "):
            self.assertEqual(
                self._get(self.au1, SUMMARY, scope=requested).status_code, 403, msg=requested
            )
        self.assertEqual(self._get(self.cert, SUMMARY, scope="COUNTRY:").status_code, 403)

    # M-7: the CISO's stored scope string is an alias for OWN_SCOPE.

    def test_ciso_stored_scope_alias(self):
        scope = resolve_scope(self.ciso, "AU|Off GBU")
        self.assertEqual((scope.key, scope.groups), ("OWN_SCOPE", ["AU", "Off GBU"]))
        with self.assertRaises(PermissionDenied):
            resolve_scope(self.au1, "AU|Off GBU")


class FixRound2Tests(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.au1, cls.au2, cls.nz1, cls.us1 = seed()
        profile(cls.au1, "AU", "APAC")
        cls.cert = User.objects.create_user("cert@meridian.example", password="x")
        in_group(cls.cert, "CERT")

    def setUp(self):
        cache.clear()

    def _ciso(self, username, scope):
        user = User.objects.create_user(username, password="x")
        in_group(user, "CISO")
        CISOProfile.objects.create(
            user=user, function="", gbu="Off GBU", country="AU", region="APAC", scope=scope
        )
        return user

    # I-5: per-user aggregate names reporters: CERT/Admin only.

    def test_user_cases_aggregate_locked(self):
        url = "/api/stats/user-cases/aggregate/"
        params = {"month": 10, "year": 2026}
        self.client.force_authenticate(self.au1)
        self.assertEqual(self.client.get(url, params).status_code, 403)
        self.client.force_authenticate(self.cert)
        self.assertEqual(self.client.get(url, params).status_code, 200)

    # M-a: the CISO's own stored scope, in any spacing, is an OWN_SCOPE alias.

    def test_single_unit_stored_scope_alias(self):
        ciso = self._ciso("c1@meridian.example", "AU")
        scope = resolve_scope(ciso, "AU")
        self.assertEqual((scope.key, scope.groups), ("OWN_SCOPE", ["AU"]))

    def test_spaced_stored_scope_alias(self):
        ciso = self._ciso("c2@meridian.example", "AU | Off GBU")
        for requested in ("AU | Off GBU", "AU|Off GBU"):
            scope = resolve_scope(ciso, requested)
            self.assertEqual((scope.key, scope.groups), ("OWN_SCOPE", ["AU", "Off GBU"]))

    def test_other_scope_string_is_403(self):
        ciso = self._ciso("c3@meridian.example", "AU|Off GBU")
        for requested in ("NZ|Off GBU", "AU", "Off GBU|AU|NZ", "NZ"):
            with self.assertRaises(PermissionDenied, msg=requested):
                resolve_scope(ciso, requested)

    # M-b

    def test_year_upper_bound_is_400(self):
        self.client.force_authenticate(self.au1)
        resp = self.client.get(SUMMARY, {"month": 10, "year": 2101})
        self.assertEqual(resp.status_code, 400)
