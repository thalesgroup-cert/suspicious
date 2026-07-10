from django.test import SimpleTestCase
from case_handler.models import Result
from score_process.scoring.engine import (
    Signal, AiSignal, band, score_case, CONF_FLOOR,
)


def sig(score, conf, mal=False, fail=False, src="x"):
    return Signal(source=src, score=score, confidence=conf, is_malicious=mal, is_failure=fail)


class BandTest(SimpleTestCase):
    def test_bands(self):
        self.assertEqual(band(0), Result.SAFE)
        self.assertEqual(band(4), Result.SAFE)
        self.assertEqual(band(5), Result.SUSPICIOUS)
        self.assertEqual(band(7), Result.SUSPICIOUS)
        self.assertEqual(band(8), Result.DANGEROUS)
        self.assertEqual(band(10), Result.DANGEROUS)


class ScoreCaseTest(SimpleTestCase):
    def test_no_signals_is_failure(self):
        v = score_case([])
        self.assertEqual(v.result, Result.FAILURE)
        self.assertEqual((v.n_scored, v.final_confidence), (0, 0))

    def test_all_failures_is_failure(self):
        v = score_case([sig(9, 90, fail=True)])
        self.assertEqual(v.result, Result.FAILURE)
        self.assertEqual(v.n_scored, 0)

    def test_hybrid_takes_max_of_worst_and_wmean(self):
        signals = [sig(9, 90, mal=True), sig(1, 80), sig(1, 80)]
        v = score_case(signals)
        self.assertEqual(v.final_score, 9)
        self.assertEqual(v.result, Result.DANGEROUS)

    def test_low_confidence_worst_ignored_for_worst_but_counts_in_mean(self):
        v = score_case([sig(9, CONF_FLOOR - 1), sig(2, 90)])
        self.assertLess(v.final_score, 8)

    def test_neutral_score_is_inconclusive(self):
        v = score_case([sig(5, 90)])
        self.assertEqual(v.result, Result.INCONCLUSIVE)

    def test_low_confidence_is_inconclusive(self):
        v = score_case([sig(7, CONF_FLOOR - 1)])
        self.assertEqual(v.result, Result.INCONCLUSIVE)

    def test_deny_list_overrides_to_dangerous(self):
        v = score_case([sig(1, 90)], deny_listed=True)
        self.assertEqual(v.result, Result.DANGEROUS)
        self.assertEqual(v.final_score, 10)

    def test_deny_list_wins_over_empty_signals(self):
        v = score_case([sig(0, 0, fail=True)], deny_listed=True)
        self.assertEqual(v.result, Result.DANGEROUS)
        self.assertEqual(v.final_score, 10)
        self.assertEqual(v.final_confidence, 100)

    def test_malicious_vote_forces_dangerous(self):
        signals = [sig(6, 90, mal=True), sig(6, 90, mal=True), sig(1, 90)]
        v = score_case(signals)
        self.assertEqual(v.result, Result.DANGEROUS)
        self.assertEqual(v.n_malicious, 2)

    def test_ai_override_when_more_confident(self):
        v = score_case([sig(1, 40)], ai=AiSignal(score=9, confidence=90))
        self.assertEqual(v.final_score, 9)
        self.assertEqual(v.result, Result.DANGEROUS)

    def test_ai_ignored_when_less_confident(self):
        v = score_case([sig(2, 95)], ai=AiSignal(score=9, confidence=10))
        self.assertEqual(v.final_score, 2)
        self.assertEqual(v.result, Result.SAFE)

    def test_confident_ai_beats_neutral_base(self):
        base = [sig(5, 85), sig(5, 80)]
        v = score_case(base, ai=AiSignal(score=6, confidence=100))
        self.assertEqual(v.final_score, 6)
        self.assertEqual(v.result, Result.SUSPICIOUS)

    def test_safe_case(self):
        v = score_case([sig(1, 90), sig(2, 90)])
        self.assertEqual(v.result, Result.SAFE)

    def test_final_score_and_result_agree_on_non_integer_mean(self):
        v = score_case([sig(4, 60), sig(5, 40)])
        self.assertEqual(v.final_score, 4)
        self.assertEqual(v.result, Result.SAFE)
