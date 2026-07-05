from django.contrib.auth import get_user_model
from django.test import TestCase
from case_handler.models import Case
from case_handler.lifecycle import LifecycleState, STATUS_MAP


class LifecycleFieldsTest(TestCase):
    def test_new_case_defaults_to_created(self):
        user = get_user_model().objects.create_user(username="lc_u", password="x")
        case = Case.objects.create(description="", reporter=user)
        self.assertEqual(case.lifecycle_state, LifecycleState.CREATED)
        self.assertIsNone(case.finalized_at)

    def test_status_map_covers_every_state(self):
        for state in LifecycleState.values:
            self.assertIn(state, STATUS_MAP)
        self.assertEqual(STATUS_MAP[LifecycleState.FINALIZED], "Done")
        self.assertEqual(STATUS_MAP[LifecycleState.CONTESTED], "Challenged")
