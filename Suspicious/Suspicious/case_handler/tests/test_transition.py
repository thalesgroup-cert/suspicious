from django.contrib.auth import get_user_model
from django.test import TestCase
from case_handler.models import Case
from case_handler.lifecycle import (
    LifecycleState, transition, IllegalTransition,
)


class TransitionTest(TestCase):
    def setUp(self):
        user = get_user_model().objects.create_user(username="tr_u", password="x")
        self.case = Case.objects.create(description="", reporter=user)

    def test_legal_transition_syncs_status(self):
        transition(self.case, LifecycleState.ANALYZING)
        self.case.refresh_from_db()
        self.assertEqual(self.case.lifecycle_state, LifecycleState.ANALYZING)
        self.assertEqual(self.case.status, "On Going")

    def test_finalize_stamps_finalized_at_and_done(self):
        transition(self.case, LifecycleState.SCORING)
        transition(self.case, LifecycleState.FINALIZED)
        self.case.refresh_from_db()
        self.assertEqual(self.case.status, "Done")
        self.assertIsNotNone(self.case.finalized_at)

    def test_illegal_transition_raises(self):
        with self.assertRaises(IllegalTransition):
            transition(self.case, LifecycleState.CONTESTED)
