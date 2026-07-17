"""Case-challenge token flow.

Covers the move of the token from the ?token= query string to a path
segment (with the legacy query form kept as a fallback), plus the
single-use / expiry guarantees of the token itself.
"""
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from case_handler.models import Case, CaseChallengeToken

User = get_user_model()


@patch("api.views.challenge.run_case_challenge")
class ChallengeTokenTests(TestCase):
    def setUp(self):
        self.reporter = User.objects.create_user(username="challenge_reporter", password="pw")
        self.case = Case.objects.create(reporter=self.reporter, description="case")

    def _issue(self):
        raw_token, _ = CaseChallengeToken.issue_token(self.case)
        return raw_token

    def test_valid_path_token_redirects_and_marks_used(self, _mock_run):
        raw = self._issue()
        resp = self.client.get(
            reverse("case-challenge", kwargs={"case_id": self.case.id, "token": raw})
        )
        self.assertEqual(resp.status_code, 302)
        token = CaseChallengeToken.objects.get(case=self.case)
        self.assertIsNotNone(token.used_at)

    def test_reused_token_is_rejected(self, _mock_run):
        raw = self._issue()
        url = reverse("case-challenge", kwargs={"case_id": self.case.id, "token": raw})
        first = self.client.get(url)
        self.assertEqual(first.status_code, 302)
        second = self.client.get(url)
        self.assertEqual(second.status_code, 400)

    def test_garbage_token_is_rejected(self, _mock_run):
        resp = self.client.get(
            reverse("case-challenge", kwargs={"case_id": self.case.id, "token": "not-a-real-token"})
        )
        self.assertEqual(resp.status_code, 400)

    def test_expired_token_is_rejected(self, _mock_run):
        raw = self._issue()
        token = CaseChallengeToken.objects.get(case=self.case)
        token.expires_at = timezone.now() - timezone.timedelta(seconds=1)
        token.save(update_fields=["expires_at"])
        resp = self.client.get(
            reverse("case-challenge", kwargs={"case_id": self.case.id, "token": raw})
        )
        self.assertEqual(resp.status_code, 400)

    def test_legacy_query_form_still_resolves(self, _mock_run):
        raw = self._issue()
        resp = self.client.get(
            reverse("case-challenge-legacy", kwargs={"case_id": self.case.id}),
            {"token": raw},
        )
        self.assertEqual(resp.status_code, 302)

    def test_build_challenge_url_uses_path_not_query(self, _mock_run):
        url = CaseChallengeToken.build_challenge_url(42, "abc123", "https://host/api")
        self.assertEqual(url, "https://host/api/cases/42/challenge/abc123/")
        self.assertNotIn("?token=", url)
