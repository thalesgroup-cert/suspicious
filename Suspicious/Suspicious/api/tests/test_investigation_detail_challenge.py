from django.contrib.auth import get_user_model
from django.test import TestCase

from case_handler.models import Case
from api.serializers.investigations import InvestigationDetailsSerializer


class InvestigationDetailChallengeFieldsTest(TestCase):
    """The InvestigationPage challenge panel reads these off GET /investigations/{id}/,
    which is backed by InvestigationDetailsSerializer — so that serializer (not the
    submissions one) must expose them, or the panel silently never renders."""

    def test_detail_exposes_challenge_proposal(self):
        user = get_user_model().objects.create_user(username="idc", password="x")
        case = Case.objects.create(
            description="", reporter=user, is_challenged=True,
            challenge_proposed_result="Dangerous", challenge_reason="phish",
        )
        data = InvestigationDetailsSerializer(case).data
        self.assertEqual(data["challenge_proposed_result"], "Dangerous")
        self.assertEqual(data["challenge_reason"], "phish")
