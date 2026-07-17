from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APITestCase
from case_handler.models import Case
from case_handler.lifecycle import LifecycleState


class SubmissionChallengeViewTest(APITestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="scv", password="x")
        self.client.force_authenticate(self.user)

    def _case(self):
        return Case.objects.create(
            description="", reporter=self.user, is_challengeable=True,
            lifecycle_state=LifecycleState.FINALIZED, status="Done", results="Safe",
        )

    @patch("api.views.submissions.notify_and_record_challenge")
    def test_stores_proposal_marks_and_notifies(self, m_notify):
        case = self._case()
        url = reverse("submission-challenge", args=[case.id])
        r = self.client.post(url, {"proposed_result": "Dangerous", "reason": "phish"}, format="json")
        self.assertEqual(r.status_code, 200, r.content)
        case.refresh_from_db()
        self.assertTrue(case.is_challenged)
        self.assertEqual(case.challenge_proposed_result, "Dangerous")
        self.assertEqual(case.challenge_reason, "phish")
        self.assertEqual(case.lifecycle_state, LifecycleState.CONTESTED)
        m_notify.assert_called_once()

    @patch("api.views.submissions.notify_and_record_challenge")
    def test_missing_proposed_result_is_400_and_no_change(self, m_notify):
        case = self._case()
        url = reverse("submission-challenge", args=[case.id])
        r = self.client.post(url, {"reason": "x"}, format="json")
        self.assertEqual(r.status_code, 400)
        case.refresh_from_db()
        self.assertFalse(case.is_challenged)
        m_notify.assert_not_called()
