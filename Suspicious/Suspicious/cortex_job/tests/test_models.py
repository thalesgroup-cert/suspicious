from django.test import TestCase

from cortex_job.models import Analyzer, AnalyzerReport


class AnalyzerTierTests(TestCase):
    def test_tier_defaults_to_contextual(self):
        a = Analyzer.objects.create(name="X", analyzer_cortex_id="x1")
        self.assertEqual(a.tier, 3)

    def test_tier_choices_accept_1_2_3(self):
        a = Analyzer.objects.create(name="Y", analyzer_cortex_id="y1", tier=1)
        a.full_clean()  # no ValidationError
        self.assertEqual(a.tier, 1)


class AnalyzerReportEnrichmentTest(TestCase):
    def test_enrichment_defaults_none_and_round_trips(self):
        a = Analyzer.objects.create(name="X", analyzer_cortex_id="x1")
        r = AnalyzerReport.objects.create(
            cortex_job_id="j", type="ip", status="Success", analyzer=a,
            level="safe", confidence=0, score=0,
            report_summary={}, report_taxonomy={}, report_full={},
        )
        self.assertIsNone(r.enrichment)
        r.enrichment = {"source": "virustotal", "malicious_count": 3}
        r.save(update_fields=["enrichment"])
        r.refresh_from_db()
        self.assertEqual(r.enrichment["malicious_count"], 3)
