# cortex_job/tests/test_reconcile_core.py
from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.test import TestCase
from case_handler.models import Case
from case_handler.lifecycle import LifecycleState
from cortex_job.cortex_utils.reconciliation import reconcile_case_core


class ReconcileCoreTest(TestCase):
    def setUp(self):
        user = get_user_model().objects.create_user(username="rc_u", password="x")
        self.case = Case.objects.create(description="", reporter=user)

    @patch("cortex_job.cortex_utils.reconciliation.finalise")
    def test_zero_jobs_finalises(self, mock_finalise):
        reconcile_case_core(self.case)
        self.case.refresh_from_db()
        self.assertEqual(self.case.lifecycle_state, LifecycleState.FINALIZED)
        self.assertEqual(self.case.status, "Done")
        mock_finalise.assert_called_once()

    @patch("cortex_job.cortex_utils.reconciliation.finalise")
    def test_terminal_case_is_noop(self, mock_finalise):
        self.case.lifecycle_state = LifecycleState.FINALIZED
        self.case.save(update_fields=["lifecycle_state"])
        reconcile_case_core(self.case)
        mock_finalise.assert_not_called()
