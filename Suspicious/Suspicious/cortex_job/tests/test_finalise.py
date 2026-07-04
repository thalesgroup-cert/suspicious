# cortex_job/tests/test_finalise.py
from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.test import TestCase
from case_handler.models import Case
from cortex_job.cortex_utils.aggregate import CaseAggregate
from cortex_job.cortex_utils.reconciliation import finalise, _describe


def _agg(total=0, success=0, failure=0, deleted=0, in_progress=0, waiting=0):
    return CaseAggregate(total=total, success=success, failure=failure,
                         deleted=deleted, in_progress=in_progress, waiting=waiting)


class DescribeTest(TestCase):
    def test_no_scored_reports_mentions_no_analyzer(self):
        self.assertIn("analyzer", _describe(_agg()).lower())

    def test_empty_ledger_but_reused_report_not_called_inapplicable(self):
        # Deduped IOC: no CaseAnalyzerJob rows (agg.scored==0) but scoring
        # reused a prior report (analysis_done>0). Must NOT say the submission
        # could not be analysed — the verdict came from a reused result.
        d = _describe(_agg(), analysis_done=1)
        self.assertIn("reused", d.lower())
        self.assertNotIn("no analyzer was applicable", d.lower())

    def test_all_success(self):
        self.assertIn("success", _describe(_agg(total=1, success=1)).lower())

    def test_all_failure(self):
        self.assertIn("failed", _describe(_agg(total=1, failure=1)).lower())

    def test_partial(self):
        d = _describe(_agg(total=3, success=2, failure=1))
        self.assertIn("2/3", d)


class FinaliseTest(TestCase):
    def setUp(self):
        user = get_user_model().objects.create_user(username="fin_u", password="x")
        self.case = Case.objects.create(description="", reporter=user)

    @patch("cortex_job.cortex_utils.reconciliation.CortexAnalyzerReports.get_report")
    def test_finalise_runs_scoring_and_sets_description(self, mock_report):
        finalise(self.case)   # real aggregate_case on a bare case -> all zeros
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
