"""Access-control regression tests.

Locks in the reporter-scoping / role-gating guarantees of the API so a
future refactor can't silently reopen cross-user data exposure:

- a reporter can read only their own submissions (IDOR)
- investigation endpoints are CERT/CISO/Admin only
- per-user dashboard stats are Admin/CERT only (closed in this branch)
- /auth/me never serialises a password or token field
"""
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from case_handler.models import Case

User = get_user_model()


def _make_user(username, *, groups=()):
    user = User.objects.create_user(username=username, password="pw-12345")
    for name in groups:
        group, _ = Group.objects.get_or_create(name=name)
        user.groups.add(group)
    return user


class SubmissionAccessTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.reporter_a = _make_user("reporter_a")
        self.reporter_b = _make_user("reporter_b")
        self.cert = _make_user("cert_user", groups=["CERT"])
        self.case_a = Case.objects.create(reporter=self.reporter_a, description="A's case")

    def test_reporter_reads_own_submission(self):
        self.client.force_authenticate(self.reporter_a)
        resp = self.client.get(
            reverse("submission-details", kwargs={"submission_id": self.case_a.id})
        )
        self.assertEqual(resp.status_code, 200)

    def test_reporter_cannot_read_other_reporters_submission(self):
        self.client.force_authenticate(self.reporter_b)
        resp = self.client.get(
            reverse("submission-details", kwargs={"submission_id": self.case_a.id})
        )
        self.assertEqual(resp.status_code, 404)

    def test_unknown_submission_is_404(self):
        self.client.force_authenticate(self.reporter_a)
        resp = self.client.get(
            reverse("submission-details", kwargs={"submission_id": 999999})
        )
        self.assertEqual(resp.status_code, 404)

    def test_elevated_user_reads_any_submission(self):
        self.client.force_authenticate(self.cert)
        resp = self.client.get(
            reverse("submission-details", kwargs={"submission_id": self.case_a.id})
        )
        self.assertEqual(resp.status_code, 200)

    def test_submission_list_is_reporter_scoped(self):
        Case.objects.create(reporter=self.reporter_b, description="B's case")
        self.client.force_authenticate(self.reporter_b)
        resp = self.client.get(reverse("submissions-list"))
        self.assertEqual(resp.status_code, 200)
        returned_ids = {row["id"] for row in resp.data["results"]}
        self.assertNotIn(self.case_a.id, returned_ids)

    def test_anonymous_cannot_list_submissions(self):
        resp = self.client.get(reverse("submissions-list"))
        self.assertIn(resp.status_code, (401, 403))


class InvestigationAccessTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.reporter = _make_user("plain_reporter")
        self.cert = _make_user("cert_invest", groups=["CERT"])

    def test_non_investigator_forbidden(self):
        self.client.force_authenticate(self.reporter)
        resp = self.client.get(reverse("investigation-list"))
        self.assertEqual(resp.status_code, 403)

    def test_investigator_allowed(self):
        self.client.force_authenticate(self.cert)
        resp = self.client.get(reverse("investigation-list"))
        self.assertEqual(resp.status_code, 200)


class CISOProfileGroupSignalTests(TestCase):
    """A CISOProfile must grant the CISO group — every RBAC check keys off it."""

    def setUp(self):
        self.client = APIClient()

    def test_profile_creation_grants_group(self):
        from profiles.models import CISOProfile

        user = _make_user("ciso_sig")
        self.assertFalse(user.groups.filter(name="CISO").exists())
        CISOProfile.objects.create(user=user)
        self.assertTrue(user.groups.filter(name="CISO").exists())

    def test_profile_deletion_revokes_group(self):
        from profiles.models import CISOProfile

        user = _make_user("ciso_sig_del")
        profile = CISOProfile.objects.create(user=user)
        profile.delete()
        self.assertFalse(user.groups.filter(name="CISO").exists())

    def test_ciso_profile_user_can_reach_investigations(self):
        from profiles.models import CISOProfile

        user = _make_user("ciso_access")
        CISOProfile.objects.create(user=user, scope="ALL")
        self.client.force_authenticate(user)
        resp = self.client.get(reverse("investigation-list"))
        self.assertEqual(resp.status_code, 200)


class CISOInvestigationScopeTests(TestCase):
    def setUp(self):
        from profiles.models import CISOProfile

        self.client = APIClient()
        # _make_user() get_or_creates each named group.
        self.emea_reporter = _make_user("emea_rep", groups=["EMEA"])
        self.apac_reporter = _make_user("apac_rep", groups=["APAC"])
        self.emea_case = Case.objects.create(reporter=self.emea_reporter, description="emea")
        self.apac_case = Case.objects.create(reporter=self.apac_reporter, description="apac")

        self.ciso = _make_user("scoped_ciso")
        self.profile = CISOProfile.objects.create(
            user=self.ciso, region="EMEA", country="FR", gbu="MG", scope="EMEA"
        )

    def _ids(self, resp):
        return {row["id"] for row in resp.data["results"]}

    def test_list_is_scope_filtered(self):
        self.client.force_authenticate(self.ciso)
        resp = self.client.get(reverse("investigation-list"))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(self._ids(resp), {self.emea_case.id})

    def test_detail_out_of_scope_is_404(self):
        self.client.force_authenticate(self.ciso)
        resp = self.client.get(
            reverse("investigation-details", kwargs={"case_id": self.apac_case.id})
        )
        self.assertEqual(resp.status_code, 404)

    def test_unset_scope_sees_nothing(self):
        self.profile.scope = "Not defined"
        self.profile.save()
        self.client.force_authenticate(self.ciso)
        resp = self.client.get(reverse("investigation-list"))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(self._ids(resp), set())

    def test_all_scope_sees_everything(self):
        self.profile.scope = "ALL"
        self.profile.save()
        self.client.force_authenticate(self.ciso)
        resp = self.client.get(reverse("investigation-list"))
        self.assertEqual(self._ids(resp), {self.emea_case.id, self.apac_case.id})

    def test_cert_is_not_scope_filtered(self):
        cert = _make_user("scope_cert", groups=["CERT"])
        self.client.force_authenticate(cert)
        resp = self.client.get(reverse("investigation-list"))
        self.assertEqual(self._ids(resp), {self.emea_case.id, self.apac_case.id})

    def test_scope_set_via_profile_patch(self):
        self.client.force_authenticate(self.ciso)
        resp = self.client.patch(reverse("profile"), {"scope": "APAC"}, format="json")
        # APAC is not one of this CISO's own org units -> rejected
        self.assertEqual(resp.status_code, 400)
        resp = self.client.patch(reverse("profile"), {"scope": "FR"}, format="json")
        self.assertEqual(resp.status_code, 200)
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.scope, "FR")


class DashboardPerUserStatsAccessTests(TestCase):
    """Regression for the per-user-stats data leak: regular reporters must
    not be able to enumerate colleague-level case counts."""

    def setUp(self):
        self.client = APIClient()
        self.reporter = _make_user("stats_reporter")
        self.cert = _make_user("stats_cert", groups=["CERT"])

    def test_regular_user_forbidden_from_per_user_stats(self):
        self.client.force_authenticate(self.reporter)
        resp = self.client.get(reverse("user-cases-list"), {"month": "05", "year": "2026"})
        self.assertEqual(resp.status_code, 403)

    def test_cert_user_allowed(self):
        self.client.force_authenticate(self.cert)
        resp = self.client.get(reverse("user-cases-list"), {"month": "05", "year": "2026"})
        self.assertEqual(resp.status_code, 200)


class MonthlyReporterStatsAccessTests(TestCase):
    """Per-reporter stats are open to every authenticated user (dashboard
    parity with monthly-cases/total-cases)."""

    def setUp(self):
        self.client = APIClient()
        self.reporter = _make_user("rep_stats_user")
        self.cert = _make_user("rep_stats_cert", groups=["CERT"])
        self.ciso = _make_user("rep_stats_ciso", groups=["CISO"])

    def test_regular_user_allowed(self):
        self.client.force_authenticate(self.reporter)
        resp = self.client.get(reverse("monthly-reporters-list"))
        self.assertEqual(resp.status_code, 200)

    def test_cert_allowed(self):
        self.client.force_authenticate(self.cert)
        resp = self.client.get(reverse("monthly-reporters-list"))
        self.assertEqual(resp.status_code, 200)

    def test_ciso_allowed(self):
        self.client.force_authenticate(self.ciso)
        resp = self.client.get(reverse("monthly-reporters-list"))
        self.assertEqual(resp.status_code, 200)

    def test_aggregate_dashboards_stay_open_to_regular_users(self):
        self.client.force_authenticate(self.reporter)
        for name in ("monthly-cases-list", "total-cases-list"):
            resp = self.client.get(reverse(name))
            self.assertEqual(resp.status_code, 200, f"{name} should stay open")


class TopPrefixesAccessTests(TestCase):
    """Per-user/group case-count ranking is open to every authenticated user,
    same as the other dashboard aggregates."""

    def setUp(self):
        self.client = APIClient()
        self.reporter = _make_user("prefixes_reporter")
        self.cert = _make_user("prefixes_cert", groups=["CERT"])

    def test_regular_user_allowed(self):
        self.client.force_authenticate(self.reporter)
        resp = self.client.get(reverse("top-prefixes"), {"type": "user"})
        self.assertEqual(resp.status_code, 200)

    def test_cert_user_allowed(self):
        self.client.force_authenticate(self.cert)
        resp = self.client.get(reverse("top-prefixes"), {"type": "user"})
        self.assertEqual(resp.status_code, 200)


class DashboardSummaryTopPrefixesTests(TestCase):
    """DashboardSummaryView embeds top_prefixes in every response, unscrubbed,
    for every authenticated user."""

    def setUp(self):
        self.client = APIClient()
        self.reporter = _make_user("summary_reporter")
        self.cert = _make_user("summary_cert", groups=["CERT"])

    def _get(self):
        return self.client.get(reverse("dashboard-summary"), {"month": 5, "year": 2026})

    def test_regular_user_request_succeeds(self):
        self.client.force_authenticate(self.reporter)
        resp = self._get()
        self.assertEqual(resp.status_code, 200)

    def test_elevated_user_request_succeeds(self):
        self.client.force_authenticate(self.cert)
        resp = self._get()
        self.assertEqual(resp.status_code, 200)


class CampaignAccessTests(TestCase):
    """Campaign analytics (threat-intel) are CERT/CISO/Admin only."""

    def setUp(self):
        self.client = APIClient()
        self.reporter = _make_user("camp_reporter")
        self.cert = _make_user("camp_cert", groups=["CERT"])

    def test_regular_user_forbidden_from_all_campaign_endpoints(self):
        self.client.force_authenticate(self.reporter)
        for name in ("campaign-classification-counts", "campaign-pca", "campaign-mail-volume"):
            resp = self.client.get(reverse(name))
            self.assertEqual(resp.status_code, 403, f"{name} must be forbidden for a reporter")

    def test_elevated_user_passes_permission_gate(self):
        self.client.force_authenticate(self.cert)
        resp = self.client.get(reverse("campaign-classification-counts"))
        self.assertNotEqual(resp.status_code, 403)


class IdentitySerializerExposureTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = _make_user("identity_user")

    def test_me_does_not_leak_password_or_token(self):
        self.client.force_authenticate(self.user)
        resp = self.client.get(reverse("me"))
        self.assertEqual(resp.status_code, 200)
        for forbidden in ("password", "token", "is_superuser", "user_permissions"):
            self.assertNotIn(forbidden, resp.data)

    def test_me_requires_authentication(self):
        resp = self.client.get(reverse("me"))
        self.assertIn(resp.status_code, (401, 403))
