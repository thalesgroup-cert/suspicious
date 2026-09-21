"""Task 3: the categorical engine names the decisive rule on its verdicts."""
from django.test import SimpleTestCase

from score_process.scoring.observable_engine import score_observable, score_group
from score_process.scoring.sources import SourceVerdict


def sv(name, tier, verdict, conf=80):
    return SourceVerdict(name=name, tier=tier, weight=0.2, verdict=verdict,
                         confidence=conf, failed=False, evidence="")


class EngineRuleTest(SimpleTestCase):
    def test_tier1_malicious_rule(self):
        v = score_observable([sv("GTI", 1, "malicious")])
        self.assertEqual(v.band, "Dangerous")
        self.assertEqual(v.rule, "tier1-authoritative-malicious")

    def test_tier1_clean_rule(self):
        v = score_observable([sv("GTI", 1, "clean")])
        self.assertEqual(v.band, "Safe")
        self.assertEqual(v.rule, "tier1-authoritative-clean")

    def test_thin_coverage_rule(self):
        v = score_observable([])
        self.assertEqual(v.band, "Inconclusive")
        self.assertEqual(v.rule, "thin-coverage")

    def test_contextual_only_flag_rule(self):
        v = score_observable([sv("X", 3, "suspicious")])
        self.assertEqual(v.band, "Suspicious")
        self.assertEqual(v.rule, "contextual-only-flag")

    def test_group_rule(self):
        g = score_group([score_observable([sv("GTI", 1, "malicious")])])
        self.assertEqual(g.band, "Dangerous")
        self.assertEqual(g.rule, "group-worst-of")
