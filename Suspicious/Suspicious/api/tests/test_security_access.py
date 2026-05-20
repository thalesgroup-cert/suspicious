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
        self.assertEqual(resp.status_code, 403)

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
