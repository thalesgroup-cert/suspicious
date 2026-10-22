"""Case-challenge token flow.

The emailed link opens a form (GET never changes anything, so mail scanners and
link previews cannot burn the token); the POST needs a reason and a proposed
verdict, spends the token and challenges the case together.
"""
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from case_handler.models import Case, CaseChallengeToken, CaseComment

User = get_user_model()
GOOD = {"proposed_result": "Safe", "reason": "This is a newsletter I subscribed to."}


@patch("api.views.challenge.notify_and_record_challenge")
class ChallengeTokenTests(TestCase):
    def setUp(self):
        self.reporter = User.objects.create_user(username="challenge_reporter", password="pw")
        self.case = Case.objects.create(reporter=self.reporter, description="case", results="Dangerous")
        self.raw, _ = CaseChallengeToken.issue_token(self.case)
        self.url = reverse("case-challenge", kwargs={"case_id": self.case.id, "token": self.raw})

    def _used(self):
        return CaseChallengeToken.objects.get(case=self.case).used_at is not None

    def test_get_shows_the_form_and_changes_nothing(self, notify):
        resp = self.client.get(self.url)
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'name="reason"')
        self.assertContains(resp, "Dangerous")
        self.case.refresh_from_db()
        self.assertFalse(self.case.is_challenged)
        self.assertFalse(self._used())
        notify.assert_not_called()

    def test_post_challenges_spends_the_token_and_writes_the_timeline(self, notify):
        resp = self.client.post(self.url, GOOD)
        self.assertEqual(resp.status_code, 302)
        self.case.refresh_from_db()
        self.assertTrue(self.case.is_challenged)
        self.assertEqual((self.case.challenge_proposed_result, self.case.challenge_reason),
                         ("Safe", GOOD["reason"]))
        self.assertTrue(self._used())
        self.assertIn(GOOD["reason"], CaseComment.objects.get(case=self.case).body)
        notify.assert_called_once()

    def test_reason_is_required_and_the_link_stays_usable(self, notify):
        for bad in ({"proposed_result": "Safe"}, {"proposed_result": "Safe", "reason": "no"},
                    {"reason": GOOD["reason"]}, {"proposed_result": "Suspicious", "reason": GOOD["reason"]}):
            resp = self.client.post(self.url, bad)
            self.assertEqual(resp.status_code, 400, bad)
            self.assertContains(resp, 'name="reason"', status_code=400)
        self.case.refresh_from_db()
        self.assertFalse(self.case.is_challenged)
        self.assertFalse(self._used())
        self.assertEqual(self.client.post(self.url, GOOD).status_code, 302)

    def test_reused_token_is_rejected(self, notify):
        self.client.post(self.url, GOOD)
        self.assertEqual(self.client.post(self.url, GOOD).status_code, 400)
        self.assertEqual(self.client.get(self.url).status_code, 400)

    def test_garbage_and_expired_tokens_are_rejected_the_same_way(self, notify):
        garbage = reverse("case-challenge", kwargs={"case_id": self.case.id, "token": "nope"})
        self.assertEqual(self.client.get(garbage).status_code, 400)
        self.assertEqual(self.client.post(garbage, GOOD).status_code, 400)
        CaseChallengeToken.objects.update(expires_at=timezone.now() - timezone.timedelta(seconds=1))
        self.assertEqual(self.client.get(self.url).status_code, 400)
        self.assertEqual(self.client.post(self.url, GOOD).status_code, 400)

    def test_already_challenged_case_is_a_conflict_and_keeps_the_token(self, notify):
        Case.objects.filter(pk=self.case.pk).update(is_challenged=True)
        self.assertEqual(self.client.get(self.url).status_code, 409)
        self.assertEqual(self.client.post(self.url, GOOD).status_code, 409)
        self.assertFalse(self._used())

    def test_a_failed_alert_does_not_undo_the_challenge(self, notify):
        notify.side_effect = RuntimeError("TheHive down")
        self.assertEqual(self.client.post(self.url, GOOD).status_code, 302)
        self.case.refresh_from_db()
        self.assertTrue(self.case.is_challenged)

    def test_legacy_query_form_still_resolves(self, notify):
        legacy = reverse("case-challenge-legacy", kwargs={"case_id": self.case.id})
        self.assertEqual(self.client.get(legacy, {"token": self.raw}).status_code, 200)
        self.assertEqual(self.client.post(f"{legacy}?token={self.raw}", GOOD).status_code, 302)

    def test_build_challenge_url_uses_path_not_query(self, notify):
        url = CaseChallengeToken.build_challenge_url(42, "abc123", "https://host/api")
        self.assertEqual(url, "https://host/api/cases/42/challenge/abc123/")
        self.assertNotIn("?token=", url)
