# cortex_job/tests/test_aggregate.py
from django.contrib.auth import get_user_model
from django.test import TestCase
from case_handler.models import Case
from cortex_job.models import Analyzer, AnalyzerReport, CaseAnalyzerJob
from cortex_job.cortex_utils.aggregate import aggregate_case


class CaseAggregateTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="agg_u", password="x")
        self.case = Case.objects.create(description="", reporter=self.user)
        self.analyzer = Analyzer.objects.create(name="A_1", analyzer_cortex_id="A_1")

    def _job(self, status, jid):
        r = AnalyzerReport.objects.create(
            cortex_job_id=jid,
            type="ip",
            status=status,
            analyzer=self.analyzer,
            level="info",
            confidence=0,
            score=0,
            report_summary={},
            report_taxonomy={},
            report_full={},
        )
        return CaseAnalyzerJob.objects.create(
            case=self.case, cortex_job_id=jid, analyzer=self.analyzer,
            analyzer_report=r, status=status,
        )

    def test_counts_by_status(self):
        for i, s in enumerate(["Success", "Success", "Failure", "InProgress",
                               "Waiting", "Deleted"]):
            self._job(s, f"j{i}")
        agg = aggregate_case(self.case)
        self.assertEqual(agg.total, 6)
        self.assertEqual(agg.success, 2)
        self.assertEqual(agg.failure, 1)
        self.assertEqual(agg.in_progress, 1)
        self.assertEqual(agg.waiting, 1)
        self.assertEqual(agg.deleted, 1)
        self.assertEqual(agg.pending, 2)      # in_progress + waiting
        self.assertEqual(agg.scored, 5)       # total - deleted

    def test_zero_jobs(self):
        agg = aggregate_case(self.case)
        self.assertEqual((agg.total, agg.pending, agg.scored), (0, 0, 0))
