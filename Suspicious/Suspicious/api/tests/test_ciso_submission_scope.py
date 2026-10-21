"""Submission endpoints apply the same CISO scope as the investigation views.

Rule (api.permissions.submissions.submission_queryset):
- reporter: own submissions
- CERT/Admin: every submission
- CISO: own submissions plus those whose reporter is in the CISO's scope
  (scope "ALL" = every submission; unset scope or no CISOProfile = own only)
"""
from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from api.tests.test_url_ondemand import _build_case_with_non_file_ioc, _make_url
from case_handler.models import Case, CaseComment
from profiles.models import CISOProfile

User = get_user_model()


def _user(username, groups=()):
    user = User.objects.create_user(username=username, password="pw-12345")
    for name in groups:
        group, _ = Group.objects.get_or_create(name=name)
        user.groups.add(group)
    return user


class CisoSubmissionScopeBase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.emea_reporter = _user("ss_emea_rep", groups=["EMEA"])
        self.apac_reporter = _user("ss_apac_rep", groups=["APAC"])
        self.ciso = _user("ss_ciso")
        self.profile = CISOProfile.objects.create(
            user=self.ciso, region="EMEA", country="FR", gbu="MG", scope="EMEA"
        )
        self.url_in = _make_url("https://in-scope.example.com/")
        self.url_out = _make_url("https://out-of-scope.example.com/")
        self.in_scope = _build_case_with_non_file_ioc(self.emea_reporter, self.url_in)
        self.out_scope = _build_case_with_non_file_ioc(self.apac_reporter, self.url_out)

    def as_user(self, user):
        self.client.force_authenticate(user)
        return self.client

    def set_scope(self, scope):
        self.profile.scope = scope
        self.profile.save()


class SubmissionListAndDetailScopeTests(CisoSubmissionScopeBase):
    def _list_ids(self, user, **params):
        resp = self.as_user(user).get(reverse("submissions-list"), params)
        self.assertEqual(resp.status_code, 200)
        return {row["id"] for row in resp.data["results"]}

    def test_list_contains_only_in_scope_cases(self):
        self.assertEqual(self._list_ids(self.ciso), {self.in_scope.id})

    def test_list_search_cannot_reach_out_of_scope_cases(self):
        self.assertEqual(self._list_ids(self.ciso, search="out-of-scope.example.com"), set())

    def test_list_keeps_own_submission_outside_scope(self):
        own = Case.objects.create(reporter=self.ciso, description="mine")
        self.assertEqual(self._list_ids(self.ciso), {self.in_scope.id, own.id})

    def test_all_scope_sees_everything(self):
        self.set_scope("ALL")
        self.assertEqual(self._list_ids(self.ciso), {self.in_scope.id, self.out_scope.id})

    def test_unset_scope_sees_only_own(self):
        self.set_scope("Not defined")
        own = Case.objects.create(reporter=self.ciso, description="mine")
        self.assertEqual(self._list_ids(self.ciso), {own.id})

    def test_missing_profile_sees_only_own(self):
        orphan = _user("ss_orphan_ciso", groups=["CISO"])
        own = Case.objects.create(reporter=orphan, description="mine")
        self.assertEqual(self._list_ids(orphan), {own.id})

    def test_cert_and_ciso_user_is_global(self):
        both = _user("ss_cert_ciso", groups=["CERT", "CISO"])
        self.assertEqual(self._list_ids(both), {self.in_scope.id, self.out_scope.id})

    def test_cert_sees_everything_and_reporter_only_own(self):
        cert = _user("ss_cert", groups=["CERT"])
        self.assertEqual(self._list_ids(cert), {self.in_scope.id, self.out_scope.id})
        self.assertEqual(self._list_ids(self.emea_reporter), {self.in_scope.id})

    def test_detail_in_scope_ok_out_of_scope_404(self):
        client = self.as_user(self.ciso)
        ok = client.get(reverse("submission-details", kwargs={"submission_id": self.in_scope.id}))
        self.assertEqual(ok.status_code, 200)
        no = client.get(reverse("submission-details", kwargs={"submission_id": self.out_scope.id}))
        self.assertEqual(no.status_code, 404)

    def test_verdict_in_scope_ok_out_of_scope_404(self):
        client = self.as_user(self.ciso)
        ok = client.get(reverse("submission-verdict", kwargs={"submission_id": self.in_scope.id}))
        self.assertEqual(ok.status_code, 200)
        no = client.get(reverse("submission-verdict", kwargs={"submission_id": self.out_scope.id}))
        self.assertEqual(no.status_code, 404)

    def test_ticket_in_scope_ok_out_of_scope_404(self):
        client = self.as_user(self.ciso)
        ok = client.get(reverse("submission-ticket", kwargs={"submission_id": self.in_scope.id}))
        self.assertEqual(ok.status_code, 200)
        no = client.get(reverse("submission-ticket", kwargs={"submission_id": self.out_scope.id}))
        self.assertEqual(no.status_code, 404)

    def test_ticket_on_own_submission_is_404_for_a_ciso(self):
        # A CISO reporting their own mail is a reporter, not an analyst.
        own = Case.objects.create(reporter=self.ciso, description="mine")
        client = self.as_user(self.ciso)
        url = reverse("submission-ticket", kwargs={"submission_id": own.id})
        self.assertEqual(client.get(url).status_code, 404)
        self.assertEqual(client.post(url).status_code, 404)

    def test_ticket_post_out_of_scope_is_404(self):
        url = reverse("submission-ticket", kwargs={"submission_id": self.out_scope.id})
        self.assertEqual(self.as_user(self.ciso).post(url).status_code, 404)

    def test_ticket_for_cert_unchanged(self):
        cert = _user("ss_cert", groups=["CERT"])
        url = reverse("submission-ticket", kwargs={"submission_id": self.out_scope.id})
        self.assertEqual(self.as_user(cert).get(url).status_code, 200)


class CaseScopedEndpointTests(CisoSubmissionScopeBase):
    def test_comments_in_scope_ok_out_of_scope_404(self):
        client = self.as_user(self.ciso)
        with mock.patch("api.views.comments.sync_case_comment_to_thehive"):
            ok = client.post(
                reverse("case-comments", kwargs={"case_id": self.in_scope.id}),
                {"body": "triage note"}, format="json",
            )
            self.assertEqual(ok.status_code, 201)
            read = client.get(reverse("case-comments", kwargs={"case_id": self.in_scope.id}))
            self.assertEqual(read.status_code, 200)
            no_post = client.post(
                reverse("case-comments", kwargs={"case_id": self.out_scope.id}),
                {"body": "nope"}, format="json",
            )
        self.assertEqual(no_post.status_code, 404)
        no_get = client.get(reverse("case-comments", kwargs={"case_id": self.out_scope.id}))
        self.assertEqual(no_get.status_code, 404)

    def test_report_html_and_markdown(self):
        client = self.as_user(self.ciso)
        for name, query in (("case-report", "?format=html"), ("case-report-markdown", "")):
            with self.subTest(view=name):
                ok = client.get(reverse(name, kwargs={"case_id": self.in_scope.id}) + query)
                self.assertEqual(ok.status_code, 200)
                no = client.get(reverse(name, kwargs={"case_id": self.out_scope.id}) + query)
                self.assertEqual(no.status_code, 404)

    def test_mail_preview(self):
        # In scope reaches the mail lookup; out of scope looks like a missing case.
        client = self.as_user(self.ciso)
        ok = client.get(reverse("case-mail-preview", kwargs={"case_id": self.in_scope.id}))
        self.assertEqual(ok.status_code, 404)
        self.assertEqual(ok.data["detail"], "No mail linked to case")
        no = client.get(reverse("case-mail-preview", kwargs={"case_id": self.out_scope.id}))
        self.assertEqual(no.status_code, 404)
        self.assertEqual(no.data["detail"], "Case not found")

    def test_screenshot(self):
        # In scope with no captured screenshot says so; out of scope looks like a missing case.
        client = self.as_user(self.ciso)
        ok = client.get(reverse("case-screenshot", kwargs={"case_id": self.in_scope.id}))
        self.assertEqual(ok.status_code, 404)
        self.assertEqual(ok.data["detail"], "No screenshot available")
        no = client.get(reverse("case-screenshot", kwargs={"case_id": self.out_scope.id}))
        self.assertEqual(no.status_code, 404)
        self.assertEqual(no.data["detail"], "Case not found")

    @mock.patch("api.views.url_analysis.CortexJob")
    def test_url_analysis(self, cortex):
        cortex.return_value.launch_cortex_jobs.return_value = None
        client = self.as_user(self.ciso)
        ok = client.post(f"/api/submissions/{self.in_scope.id}/urls/{self.url_in.id}/analyze/")
        self.assertEqual(ok.status_code, 202)
        no = client.post(f"/api/submissions/{self.out_scope.id}/urls/{self.url_out.id}/analyze/")
        self.assertEqual(no.status_code, 404)

    def test_cert_keeps_global_access_on_case_endpoints(self):
        client = self.as_user(_user("ss_cert_ep", groups=["CERT"]))
        for case in (self.in_scope, self.out_scope):
            resp = client.get(reverse("case-report", kwargs={"case_id": case.id}) + "?format=html")
            self.assertEqual(resp.status_code, 200)

    def test_reporter_keeps_own_access_and_is_denied_others(self):
        client = self.as_user(self.apac_reporter)
        own = client.get(reverse("case-report", kwargs={"case_id": self.out_scope.id}) + "?format=html")
        self.assertEqual(own.status_code, 200)
        other = client.get(reverse("case-report", kwargs={"case_id": self.in_scope.id}) + "?format=html")
        self.assertEqual(other.status_code, 404)

    def test_ciso_keeps_own_out_of_scope_submission(self):
        mine = _build_case_with_non_file_ioc(self.ciso, _make_url("https://mine.example.com/"))
        client = self.as_user(self.ciso)
        resp = client.get(reverse("case-report", kwargs={"case_id": mine.id}) + "?format=html")
        self.assertEqual(resp.status_code, 200)


class ElevatedExtrasScopeTests(CisoSubmissionScopeBase):
    """A CISO on their own submission gets the reporter view; in scope, the analyst view."""

    def setUp(self):
        super().setUp()
        self.own = Case.objects.create(reporter=self.ciso, description="mine")
        for case in (self.own, self.in_scope):
            CaseComment.objects.create(case=case, author=self.emea_reporter, body="public", is_internal=False)
            CaseComment.objects.create(case=case, author=self.emea_reporter, body="secret", is_internal=True)

    def _detail(self, user, case):
        return self.as_user(user).get(reverse("submission-details", kwargs={"submission_id": case.id}))

    def _bodies(self, user, case):
        resp = self.as_user(user).get(reverse("case-comments", kwargs={"case_id": case.id}))
        self.assertEqual(resp.status_code, 200)
        return {c["body"] for c in resp.data}

    def test_own_case_detail_has_no_raw_but_in_scope_has(self):
        self.assertIsNone(self._detail(self.ciso, self.own).data.get("raw"))
        self.assertIsNotNone(self._detail(self.ciso, self.in_scope).data.get("raw"))

    def test_own_case_hides_internal_comments_in_scope_shows_them(self):
        self.assertEqual(self._bodies(self.ciso, self.own), {"public"})
        self.assertEqual(self._bodies(self.ciso, self.in_scope), {"public", "secret"})

    def test_own_case_comment_is_not_internal_in_scope_comment_is(self):
        client = self.as_user(self.ciso)
        with mock.patch("api.views.comments.sync_case_comment_to_thehive") as sync:
            mine = client.post(reverse("case-comments", kwargs={"case_id": self.own.id}), {"body": "m"}, format="json")
            scoped = client.post(reverse("case-comments", kwargs={"case_id": self.in_scope.id}), {"body": "s"}, format="json")
        self.assertEqual((mine.status_code, scoped.status_code), (201, 201))
        self.assertFalse(CaseComment.objects.get(body="m").is_internal)
        self.assertTrue(CaseComment.objects.get(body="s").is_internal)

    def test_cert_and_ciso_keeps_extras_on_own_case(self):
        both = _user("ss_cert_ciso2", groups=["CERT", "CISO"])
        mine = Case.objects.create(reporter=both, description="m")
        CaseComment.objects.create(case=mine, author=both, body="secret", is_internal=True)
        self.assertIn("secret", self._bodies(both, mine))
        self.assertIsNotNone(self._detail(both, mine).data.get("raw"))


class SubmissionListQueryCountTests(CisoSubmissionScopeBase):
    def _count(self):
        from django.db import connection
        from django.test.utils import CaptureQueriesContext

        client = self.as_user(self.ciso)
        with CaptureQueriesContext(connection) as ctx:
            self.assertEqual(client.get(reverse("submissions-list")).status_code, 200)
        return len(ctx)

    def test_list_query_count_is_constant_in_rows(self):
        self._count()  # warm caches
        before = self._count()
        for i in range(5):
            _build_case_with_non_file_ioc(self.emea_reporter, _make_url(f"https://more{i}.example.com/"))
        self.assertEqual(self._count(), before)
