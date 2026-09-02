from django.test import TestCase

from cortex_job.models import Analyzer


class AnalyzerTierTests(TestCase):
    def test_tier_defaults_to_contextual(self):
        a = Analyzer.objects.create(name="X", analyzer_cortex_id="x1")
        self.assertEqual(a.tier, 3)

    def test_tier_choices_accept_1_2_3(self):
        a = Analyzer.objects.create(name="Y", analyzer_cortex_id="y1", tier=1)
        a.full_clean()  # no ValidationError
        self.assertEqual(a.tier, 1)
