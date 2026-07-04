from django.contrib.auth import get_user_model
from django.test import TestCase

from case_handler.models import Case, Result
from score_process.scoring.apply import apply_verdict
from score_process.scoring.engine import CaseVerdict


class ApplyVerdictTest(TestCase):
    def test_writes_case_fields(self):
        user = get_user_model().objects.create_user(username="ap_u", password="x")
        case = Case.objects.create(description="", reporter=user)
        v = CaseVerdict(final_score=9, final_confidence=90,
                        result=Result.DANGEROUS, n_malicious=2, n_scored=4)
        apply_verdict(case, v)
        case.refresh_from_db()
        self.assertEqual(case.results, Result.DANGEROUS)
        self.assertEqual(case.final_score, 9)
        self.assertEqual(case.final_confidence, 90)
        self.assertEqual(case.score, 9)           # legacy mirror of final_score
        self.assertEqual(case.confidence, 90)     # legacy mirror of final_confidence
        self.assertEqual(case.analysis_done, 4)
        self.assertTrue(case.kpi_counted)     # SP2 idempotent KPI ran once
