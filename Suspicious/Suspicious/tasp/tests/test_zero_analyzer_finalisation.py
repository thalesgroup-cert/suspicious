"""Regression tests for the zero-analyzer finalisation gap.

A submission whose observable matches no enabled Cortex analyzer produces
zero CaseAnalyzerJob rows. Before the fix, such a case hung in "On Going"
forever (every finalise path was keyed on a CaseAnalyzerJob) and displayed
the fail-dangerous default verdict "Suspicious".
"""
from django.contrib.auth import get_user_model
from django.test import TestCase

from case_handler.models import Case
from cortex_job.cortex_utils.cortex_and_job_management import CortexJobManager
from score_process.scoring.update_handler import update_case_results

_BUCKETS = ("reports", "success", "inprogress", "failure", "waiting", "deleted")


def _totals(**buckets):
    total = {k: set() for k in _BUCKETS}
    for name, ids in buckets.items():
        total[name] = set(ids)
    return {"total": total}


class ZeroAnalyzerFinalisationTest(TestCase):
    def setUp(self):
        User = get_user_model()
        self.reporter = User.objects.create_user(username="zero_an_user", password="x")
        self.case = Case.objects.create(
            status="On Going", description="", reporter=self.reporter
        )

    def test_zero_reports_marks_case_done(self):
        """No dispatched analyzers → case finishes instead of hanging."""
        mgr = CortexJobManager()
        mgr.results = _totals()  # no reports at all
        mgr.generate_description(self.case)
        self.case.refresh_from_db()
        self.assertEqual(self.case.status, "Done")
        self.assertIn("analyzer", self.case.description.lower())

    def test_pending_report_keeps_case_ongoing(self):
        """A still-running analyzer must keep the case On Going (guard against
        the fix finalising too eagerly)."""
        mgr = CortexJobManager()
        mgr.results = _totals(reports=["r1"], inprogress=["r1"])
        mgr.generate_description(self.case)
        self.case.refresh_from_db()
        self.assertEqual(self.case.status, "On Going")

    def test_no_reports_verdict_is_failure(self):
        """A case finalised with no analyzer reports resolves to Failure,
        never the fail-dangerous default Suspicious."""
        self.case.results = "Suspicious"
        update_case_results(self.case, [], is_malicious=0, failure=0)
        self.assertEqual(self.case.results, "Failure")
        self.assertEqual(self.case.analysis_done, 0)
