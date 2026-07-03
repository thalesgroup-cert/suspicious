from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase
from case_handler.models import Case
from tasp.tasks import reconcile_case


class ReconcileTaskTest(TestCase):
    def setUp(self):
        user = get_user_model().objects.create_user(username="rt_u", password="x")
        self.case = Case.objects.create(description="", reporter=user)

    @patch("tasp.tasks.reconcile_case_core")
    def test_task_invokes_core_with_loaded_case(self, mock_core):
        reconcile_case.run(self.case.id)
        self.assertEqual(mock_core.call_count, 1)
        passed = mock_core.call_args[0][0]
        self.assertEqual(passed.id, self.case.id)

    @patch("tasp.tasks.reconcile_case_core")
    def test_missing_case_is_noop(self, mock_core):
        reconcile_case.run(999999)
        mock_core.assert_not_called()

    @patch("tasp.tasks.reconcile_case_core")
    def test_lock_held_skips_core(self, mock_core):
        cache.add(f"case_update_lock:{self.case.id}", 1, timeout=120)
        try:
            reconcile_case.run(self.case.id)
            mock_core.assert_not_called()
        finally:
            cache.delete(f"case_update_lock:{self.case.id}")
