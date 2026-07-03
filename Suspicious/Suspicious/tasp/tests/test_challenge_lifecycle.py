"""Challenge flow keeps lifecycle_state authoritative (FINALIZED -> CONTESTED)."""
import logging

from django.contrib.auth import get_user_model
from django.test import TestCase

from case_handler.models import Case
from case_handler.lifecycle import LifecycleState
from tasp.services.challenge import CaseChallengeService


class ChallengeLifecycleTest(TestCase):
    def test_challenge_finalized_case_moves_to_contested(self):
        user = get_user_model().objects.create_user(username="ch_lc_u", password="x")
        case = Case.objects.create(
            description="", reporter=user,
            lifecycle_state=LifecycleState.FINALIZED, status="Done",
        )
        CaseChallengeService(case, logging.getLogger("test")).mark_challenged()
        case.refresh_from_db()
        self.assertEqual(case.lifecycle_state, LifecycleState.CONTESTED)
        self.assertEqual(case.status, "Challenged")
        self.assertTrue(case.is_challenged)
