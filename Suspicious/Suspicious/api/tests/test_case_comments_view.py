from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from case_handler.models import Case, CaseComment

User = get_user_model()


def _make_user(username, *, groups=()):
    user = User.objects.create_user(username=username, password="pw-12345")
    for name in groups:
        group, _ = Group.objects.get_or_create(name=name)
        user.groups.add(group)
    return user


class CaseCommentsViewTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.reporter = _make_user("cc_reporter")
        self.other_reporter = _make_user("cc_other_reporter")
        self.analyst = _make_user("cc_analyst", groups=["CERT"])
        self.case = Case.objects.create(reporter=self.reporter, description="")
        self.url = reverse("case-comments", kwargs={"case_id": self.case.id})

    def test_anonymous_is_401_or_403(self):
        resp = self.client.get(self.url)
        self.assertIn(resp.status_code, (401, 403))

    def test_reporter_can_read_and_create_own_case(self):
        self.client.force_authenticate(self.reporter)
        resp = self.client.post(self.url, {"body": "please check this"}, format="json")
        self.assertEqual(resp.status_code, 201)
        self.assertFalse(resp.data["is_internal"])
        resp = self.client.get(self.url)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.data), 1)

    def test_non_owner_reporter_gets_404(self):
        self.client.force_authenticate(self.other_reporter)
        resp = self.client.get(self.url)
        self.assertEqual(resp.status_code, 404)
        resp = self.client.post(self.url, {"body": "nope"}, format="json")
        self.assertEqual(resp.status_code, 404)

    def test_analyst_can_read_any_case_and_creates_internal_comments(self):
        self.client.force_authenticate(self.analyst)
        resp = self.client.post(self.url, {"body": "internal note"}, format="json")
        self.assertEqual(resp.status_code, 201)
        self.assertTrue(resp.data["is_internal"])

    def test_reporter_never_sees_internal_comments(self):
        CaseComment.objects.create(case=self.case, author=self.analyst, body="secret", is_internal=True)
        CaseComment.objects.create(case=self.case, author=self.reporter, body="visible", is_internal=False)
        self.client.force_authenticate(self.reporter)
        resp = self.client.get(self.url)
        self.assertEqual(resp.status_code, 200)
        bodies = [c["body"] for c in resp.data]
        self.assertEqual(bodies, ["visible"])

    def test_analyst_sees_all_comments(self):
        CaseComment.objects.create(case=self.case, author=self.analyst, body="secret", is_internal=True)
        CaseComment.objects.create(case=self.case, author=self.reporter, body="visible", is_internal=False)
        self.client.force_authenticate(self.analyst)
        resp = self.client.get(self.url)
        self.assertEqual(resp.status_code, 200)
        bodies = {c["body"] for c in resp.data}
        self.assertEqual(bodies, {"secret", "visible"})

    def test_blank_body_is_400(self):
        self.client.force_authenticate(self.reporter)
        resp = self.client.post(self.url, {"body": "   "}, format="json")
        self.assertEqual(resp.status_code, 400)

    def test_client_cannot_force_is_internal_true(self):
        self.client.force_authenticate(self.reporter)
        resp = self.client.post(self.url, {"body": "hi", "is_internal": True}, format="json")
        self.assertEqual(resp.status_code, 201)
        self.assertFalse(resp.data["is_internal"])

    def test_posting_a_comment_triggers_thehive_sync(self):
        self.case.thehive_alert_id = "~alert-42"
        self.case.save(update_fields=["thehive_alert_id"])
        self.client.force_authenticate(self.reporter)

        with patch("api.views.comments.sync_case_comment_to_thehive") as mock_sync:
            resp = self.client.post(self.url, {"body": "please check"}, format="json")

        self.assertEqual(resp.status_code, 201)
        mock_sync.assert_called_once()
        args, kwargs = mock_sync.call_args
        self.assertEqual(args[0].id, self.case.id)
        self.assertEqual(args[1].body, "please check")

    def test_posting_a_comment_without_alert_id_does_not_error(self):
        self.client.force_authenticate(self.reporter)

        with patch("api.views.comments.sync_case_comment_to_thehive") as mock_sync:
            resp = self.client.post(self.url, {"body": "no alert here"}, format="json")

        self.assertEqual(resp.status_code, 201)
        mock_sync.assert_called_once()
