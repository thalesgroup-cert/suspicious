"""Task 4: the weighted mail engine names the decisive rule on its verdict."""
from django.test import SimpleTestCase

from score_process.scoring.engine import AiSignal, score_case
from score_process.tests.test_engine import sig


class WeightedRuleTest(SimpleTestCase):
    def test_deny_listed_rule(self):
        v = score_case([], deny_listed=True, deny_reason="x")
        self.assertEqual(v.rule, "deny-listed")

    def test_no_scored_rule(self):
        v = score_case([])
        self.assertEqual(v.rule, "analysis-incomplete")

    def test_ai_classifier_decisive_rule(self):
        v = score_case([sig(1, 40)], ai=AiSignal(score=9, confidence=90))
        self.assertEqual(v.rule, "ai-classifier-decisive")

    def test_no_signal_rule(self):
        v = score_case([sig(1, 90), sig(2, 90)])
        self.assertEqual(v.rule, "no-signal")

    def test_single_strong_signal_rule(self):
        v = score_case([sig(9, 90), sig(1, 10), sig(1, 10)])
        self.assertEqual(v.rule, "single-strong-signal")

    def test_weighted_consensus_rule(self):
        v = score_case([sig(6, 90, mal=True), sig(6, 90, mal=True), sig(1, 90)])
        self.assertEqual(v.rule, "weighted-consensus")
