# cortex_job/tests/test_finalise.py
from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.test import TestCase
from case_handler.models import Case
from cortex_job.cortex_utils.reconciliation import finalise, _describe


class DescribeTest(TestCase):
    def _totals(self, **b):
        keys = ("reports", "success", "inprogress", "failure", "waiting", "deleted")
        t = {k: set() for k in keys}
        for name, ids in b.items():
            t[name] = set(ids)
        return {"total": t}

    def test_zero_reports_description_mentions_no_analyzer(self):
        self.assertIn("analyzer", _describe(self._totals()).lower())

    def test_all_success_description(self):
        d = _describe(self._totals(reports=["r1"], success=["r1"]))
        self.assertIn("success", d.lower())


class FinaliseTest(TestCase):
    def setUp(self):
        user = get_user_model().objects.create_user(username="fin_u", password="x")
        self.case = Case.objects.create(description="", reporter=user)

    @patch("cortex_job.cortex_utils.reconciliation.CortexAnalyzerReports.get_report")
    @patch("cortex_job.cortex_utils.reconciliation.CortexJobManager.get_results")
    def test_finalise_runs_scoring_and_sets_description(self, mock_results, mock_report):
        mock_results.return_value = None
        # get_results populates mgr.results; emulate empty buckets
        def _populate(case):
            return None
        mock_results.side_effect = _populate
        finalise(self.case)
        mock_report.assert_called_once_with(self.case)
        self.assertTrue(self.case.description)


class FinalisePersistenceTest(TestCase):
    def test_finalise_persists_failure_verdict_for_mailless_case(self):
        # A case with no mail and no analyzer reports must persist the Failure
        # verdict (regression: save_case_results early-returns for mail=None, so
        # finalise must do a full save or the verdict is lost).
        from django.contrib.auth import get_user_model
        from case_handler.models import Case
        from cortex_job.cortex_utils.reconciliation import finalise
        user = get_user_model().objects.create_user(username="fin_persist_u", password="x")
        case = Case.objects.create(description="", reporter=user, results="Suspicious")
        finalise(case)
        case.refresh_from_db()
        self.assertEqual(case.results, "Failure")
