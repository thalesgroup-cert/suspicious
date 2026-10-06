from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from case_handler.lifecycle import LifecycleState
from case_handler.models import Case
from cortex_job.cortex_utils.reconciliation import reconcile_case_core


class ReconcileDerivedTests(TestCase):
    def setUp(self):
        user = get_user_model().objects.create_user(username="rd_u", password="x")
        self.case = Case.objects.create(
            description="", reporter=user, lifecycle_state=LifecycleState.ANALYZING
        )
        self.case.dispatched_at = timezone.now()
        self.case.save(update_fields=["dispatched_at"])

    @patch("cortex_job.cortex_utils.reconciliation.ingest_derived_observables", return_value=2)
    @patch("cortex_job.cortex_utils.reconciliation.finalise")
    def test_case_stays_analyzing_when_derived_jobs_dispatched(self, m_finalise, _m_ingest):
        reconcile_case_core(self.case)
        self.case.refresh_from_db()
        self.assertEqual(self.case.lifecycle_state, LifecycleState.ANALYZING)
        m_finalise.assert_not_called()

    @patch("cortex_job.cortex_utils.reconciliation.ingest_derived_observables", return_value=0)
    @patch("cortex_job.cortex_utils.reconciliation.finalise")
    def test_case_finalizes_when_nothing_more_to_ingest(self, m_finalise, _m_ingest):
        reconcile_case_core(self.case)
        self.case.refresh_from_db()
        self.assertEqual(self.case.lifecycle_state, LifecycleState.FINALIZED)
        m_finalise.assert_called_once()
