from django.contrib.auth import get_user_model
from django.test import TestCase
from case_handler.models import Case


class ChallengeFieldsTest(TestCase):
    def test_defaults_blank(self):
        user = get_user_model().objects.create_user(username="cf_u", password="x")
        case = Case.objects.create(description="", reporter=user)
        self.assertEqual(case.challenge_proposed_result, "")
        self.assertEqual(case.challenge_reason, "")

    def test_stores_proposal(self):
        user = get_user_model().objects.create_user(username="cf_u2", password="x")
        case = Case.objects.create(
            description="", reporter=user,
            challenge_proposed_result="Dangerous", challenge_reason="looks like phishing",
        )
        case.refresh_from_db()
        self.assertEqual(case.challenge_proposed_result, "Dangerous")
        self.assertEqual(case.challenge_reason, "looks like phishing")
