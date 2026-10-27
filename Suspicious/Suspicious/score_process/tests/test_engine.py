from django.test import SimpleTestCase
from case_handler.models import Result
from score_process.scoring.engine import (
    Signal, AiSignal, Vote, band, score_case, CONF_FLOOR,
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
        v = score_case([sig(1, 90)], deny_listed=True, deny_reason="Domain deny-listed: evil.example")
        self.assertEqual(v.result, Result.DANGEROUS)
        self.assertEqual(v.final_score, 10)
        self.assertTrue(v.is_denylisted)
        self.assertEqual(v.list_reason, "Domain deny-listed: evil.example")

    def test_not_deny_listed_leaves_reason_fields_default(self):
        v = score_case([sig(1, 90)])
        self.assertFalse(v.is_denylisted)
        self.assertEqual(v.list_reason, "")

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

    def test_info_only_signal_is_safe_not_inconclusive(self):
        """Regression: an 'info'-level analyzer (e.g. FileInfo, present on
        every attachment) used to score exactly NEUTRAL(5), forcing a case
        with no other findings to Inconclusive even when nothing suspicious
        was ever found. get_level_score_confidence('info') now returns 2."""
        v = score_case([sig(2, 50)])
        self.assertEqual(v.result, Result.SAFE)

    def test_final_score_and_result_agree_on_non_integer_mean(self):
        v = score_case([sig(4, 60), sig(5, 40)])
        self.assertEqual(v.final_score, 4)
        self.assertEqual(v.result, Result.SAFE)


def vote(name, weight, band=Result.SAFE, wl=False, listed=None):
    # dissent is about an allow-listed target unless a test says otherwise
    return Vote(analyzer=name, weight=weight, band=band, whitelisted=wl,
                dissent_on_listed=(band != Result.SAFE) if listed is None else listed)


# a malicious signal elsewhere in the case: today this always means Dangerous
DANGEROUS_CASE = [sig(0, 100, src="url"), sig(0, 100, src="url"), sig(9, 90, mal=True, src="ip")]


class AllowListMajorityTest(SimpleTestCase):
    def test_baseline_is_dangerous_without_votes(self):
        self.assertEqual(score_case(DANGEROUS_CASE).result, Result.DANGEROUS)

    def test_majority_overrides_and_names_the_dissenter(self):
        votes = [vote("VT", 0.3, wl=True), vote("Urlscan", 0.3, wl=True),
                 vote("AIMailAnalyzer", 0.2, Result.DANGEROUS)]
        v = score_case(DANGEROUS_CASE, votes=votes)
        self.assertEqual((v.result, v.final_score, v.final_confidence, v.rule),
                         (Result.SAFE, 0, 100, "allow-list-majority"))
        self.assertIn("Dangerous: AIMailAnalyzer", v.rationale[-1])
        self.assertIn("75%", v.rationale[-1])

    def test_exactly_half_does_not_override_even_with_float_drift(self):
        for votes in ([vote("A", 0.5, wl=True), vote("B", 0.5, Result.DANGEROUS)],
                      [vote("A", 0.1, wl=True), vote("B", 0.2), vote("C", 0.3, Result.DANGEROUS)]):
            v = score_case(DANGEROUS_CASE, votes=votes)
            self.assertEqual(v.result, Result.DANGEROUS)
            self.assertIn("only 50%", v.rationale[-1])

    def test_minority_keeps_dangerous_and_says_why(self):
        votes = [vote("A", 0.2, wl=True), vote("B", 0.5, Result.DANGEROUS), vote("C", 0.3, Result.SUSPICIOUS)]
        v = score_case(DANGEROUS_CASE, votes=votes)
        self.assertEqual((v.result, v.rule), (Result.DANGEROUS, "weighted-consensus"))
        self.assertIn("only 20%", v.rationale[-1])

    def test_no_whitelisted_vote_is_identical_to_today(self):
        cases = [(DANGEROUS_CASE, None, False), ([sig(2, 95)], AiSignal(9, 10), False),
                 ([sig(1, 40)], AiSignal(9, 90), False), ([sig(5, 85), sig(5, 80)], AiSignal(6, 100), False),
                 ([sig(7, 40)], None, True)]
        plain = [vote("A", 1.0), vote("B", 1.0, Result.DANGEROUS)]
        for signals, ai, missing in cases:
            self.assertEqual(score_case(signals, ai, ai_missing=missing, votes=plain),
                             score_case(signals, ai, ai_missing=missing))

    def test_deny_list_zero_weight_and_already_safe_are_untouched(self):
        v = score_case(DANGEROUS_CASE, deny_listed=True, deny_reason="d", votes=[vote("A", 1, wl=True)])
        self.assertEqual((v.result, v.rule), (Result.DANGEROUS, "deny-listed"))
        self.assertEqual(score_case(DANGEROUS_CASE, votes=[vote("A", 0, wl=True)]).result, Result.DANGEROUS)
        self.assertEqual(score_case([sig(0, 100)], votes=[vote("A", 1, wl=True)]), score_case([sig(0, 100)]))

    def test_missing_ai_inconclusive_becomes_safe_on_majority(self):
        v = score_case([sig(0, 100)], ai_missing=True, votes=[vote("A", 1, wl=True)])
        self.assertEqual((v.result, v.rule), (Result.SAFE, "allow-list-majority"))

    def test_embedded_dangerous_ioc_still_raises_the_majority_verdict(self):
        from score_process.scoring.engine import mail_band_escalation
        from score_process.scoring.observable_engine import ObservableVerdict
        safe = score_case(DANGEROUS_CASE, votes=[vote("A", 1, wl=True)])
        out = mail_band_escalation(safe, [ObservableVerdict("Dangerous", 80, None, {}, [])])
        self.assertEqual((out.result, out.rule), (Result.DANGEROUS, "embedded-ioc-escalation"))


class AllowListBypassTest(SimpleTestCase):
    """One allow-listed link in a mail must not hide something flagged elsewhere in it."""

    def test_dissent_about_something_not_allow_listed_blocks_the_override(self):
        # 80% of the weight is Safe or allow-listed, which would override, but one analyzer
        # flagged a link that is not on the list.
        votes = [vote("WL", 0.4, wl=True), vote("Clean", 0.4), vote("VT", 0.2, Result.DANGEROUS, listed=False)]
        v = score_case(DANGEROUS_CASE, votes=votes)
        self.assertEqual((v.result, v.rule), (Result.DANGEROUS, "weighted-consensus"))
        self.assertIn("VT flagged something that is not allow-listed", v.rationale[-1])

    def test_the_ai_is_not_overruled_by_an_allow_listed_link(self):
        votes = [vote("WL", 0.5, wl=True), vote("AIMailAnalyzer", 0.1, Result.DANGEROUS, listed=False),
                 vote("Clean", 0.4)]
        self.assertEqual(score_case(DANGEROUS_CASE, votes=votes).result, Result.DANGEROUS)

    def test_one_unlisted_dissenter_among_listed_ones_still_blocks(self):
        votes = [vote("WL", 0.6, wl=True), vote("A", 0.1, Result.SUSPICIOUS, listed=True),
                 vote("B", 0.1, Result.DANGEROUS, listed=False), vote("C", 0.2)]
        self.assertEqual(score_case(DANGEROUS_CASE, votes=votes).result, Result.DANGEROUS)

    def test_dissent_only_about_listed_targets_is_still_overruled(self):
        votes = [vote("WL", 0.4, wl=True), vote("Clean", 0.4), vote("VT", 0.2, Result.DANGEROUS, listed=True)]
        v = score_case(DANGEROUS_CASE, votes=votes)
        self.assertEqual((v.result, v.rule), (Result.SAFE, "allow-list-majority"))


class AllowListPercentAndSuspiciousTest(SimpleTestCase):
    def test_percentage_never_contradicts_the_decision(self):
        # 50.04% is an override: must not print as 50 or lower
        v = score_case(DANGEROUS_CASE, votes=[vote("A", 5004, wl=True), vote("B", 4996, Result.DANGEROUS)])
        self.assertEqual(v.rule, "allow-list-majority")
        self.assertIn("50.1%", v.rationale[-1])
        # 49.96% is not: must not print as 50
        v = score_case(DANGEROUS_CASE, votes=[vote("A", 4996, wl=True), vote("B", 5004, Result.DANGEROUS)])
        self.assertEqual(v.result, Result.DANGEROUS)
        self.assertIn("only 49.9%", v.rationale[-1])

    def test_whitelisted_vote_on_a_suspicious_result(self):
        case = [sig(6, 90, src="url")]
        self.assertEqual(score_case(case).result, Result.SUSPICIOUS)
        v = score_case(case, votes=[vote("A", 0.6, wl=True), vote("B", 0.4, Result.SUSPICIOUS)])
        self.assertEqual((v.result, v.rule), (Result.SAFE, "allow-list-majority"))
        v = score_case(case, votes=[vote("A", 0.4, wl=True), vote("B", 0.6, Result.SUSPICIOUS)])
        self.assertEqual(v.result, Result.SUSPICIOUS)
        self.assertIn("only 40%", v.rationale[-1])
