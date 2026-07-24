from django.contrib.auth import get_user_model
from django.test import TestCase

from case_handler.lifecycle import LifecycleState, transition
from case_handler.models import Case

User = get_user_model()


class RedoLifecycleTransitionTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="lc_user", password="pw-12345")

    def test_finalized_can_transition_to_analyzing(self):
        case = Case.objects.create(
            reporter=self.user, description="", lifecycle_state=LifecycleState.FINALIZED,
        )
        transition(case, LifecycleState.ANALYZING)
        case.refresh_from_db()
        self.assertEqual(case.lifecycle_state, LifecycleState.ANALYZING)

    def test_contested_can_transition_to_analyzing(self):
        case = Case.objects.create(
            reporter=self.user, description="", lifecycle_state=LifecycleState.CONTESTED,
        )
        transition(case, LifecycleState.ANALYZING)
        case.refresh_from_db()
        self.assertEqual(case.lifecycle_state, LifecycleState.ANALYZING)

    def test_finalized_to_contested_still_works(self):
        """Guard against the new edge accidentally replacing the existing one."""
        case = Case.objects.create(
            reporter=self.user, description="", lifecycle_state=LifecycleState.FINALIZED,
        )
        transition(case, LifecycleState.CONTESTED)
        case.refresh_from_db()
        self.assertEqual(case.lifecycle_state, LifecycleState.CONTESTED)
