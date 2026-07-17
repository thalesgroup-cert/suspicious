from django.contrib.auth import get_user_model
from django.test import TestCase
from case_handler.models import Case
from api.serializers.submissions import SubmissionDetailsSerializer


class DetailChallengeFieldsTest(TestCase):
    def test_detail_exposes_challenge_proposal(self):
        user = get_user_model().objects.create_user(username="dcf", password="x")
        case = Case.objects.create(
            description="", reporter=user, is_challenged=True,
            challenge_proposed_result="Dangerous", challenge_reason="phish",
        )
        data = SubmissionDetailsSerializer(case).data
        self.assertEqual(data["challenge_proposed_result"], "Dangerous")
        self.assertEqual(data["challenge_reason"], "phish")
