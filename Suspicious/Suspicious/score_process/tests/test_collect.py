from django.contrib.auth import get_user_model
from django.test import TestCase

from case_handler.models import Case, CaseHasNonFileIocs
from cortex_job.models import Analyzer, AnalyzerReport
from ip_process.models import IP
from score_process.scoring.collect import collect_signals
from score_process.scoring.engine import Signal


class CollectSignalsTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="cs_u", password="x")

    def test_ioc_only_case_yields_one_signal(self):
        ip = IP.objects.create(address="203.0.113.7")
        analyzer = Analyzer.objects.create(name="Abuse", analyzer_cortex_id="Abuse", weight=1)
        AnalyzerReport.objects.create(
            cortex_job_id="j1", type="ip", status="Success", analyzer=analyzer,
            ip=ip, level="malicious", confidence=9, score=9,
            report_summary={"taxonomies": [{"level": "malicious", "value": "abuse"}]},
            report_taxonomy={}, report_full={},
        )
        case = Case.objects.create(description="", reporter=self.user)
        iocs = CaseHasNonFileIocs.objects.create(case=case, ip=ip)
        case.nonFileIocs = iocs
        case.save()

        signals, ai, deny_listed, ai_missing = collect_signals(case)

        self.assertTrue(all(isinstance(s, Signal) for s in signals))
        self.assertEqual(len(signals), 1)
        self.assertTrue(signals[0].is_malicious)
        self.assertLessEqual(signals[0].confidence, 100)
        self.assertEqual(signals[0].confidence, 100)
        self.assertFalse(deny_listed)

    def test_no_iocs_yields_no_signals(self):
        case = Case.objects.create(description="", reporter=self.user)
        signals, ai, deny_listed, ai_missing = collect_signals(case)
        self.assertEqual(signals, [])
        self.assertFalse(deny_listed)

    def test_ai_confidence_is_already_0_100(self):
        case = Case.objects.create(
            description="", reporter=self.user, score_ai=6, confidence_ai=100,
        )
        _, ai, _, _ = collect_signals(case)
        self.assertIsNotNone(ai)
        self.assertEqual(ai.confidence, 100)
        self.assertEqual(ai.score, 6)

    def test_ai_confidence_clamped_to_100(self):
        case = Case.objects.create(
            description="", reporter=self.user, score_ai=6, confidence_ai=150,
        )
        _, ai, _, _ = collect_signals(case)
        self.assertEqual(ai.confidence, 100)
