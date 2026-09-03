from django.test import SimpleTestCase

from score_process.scoring.sources import SourceVerdict
from score_process.scoring.observable_engine import score_observable, score_group, ObservableVerdict


def sv(verdict, tier=3, weight=0.2, confidence=None, failed=False, name="s"):
    return SourceVerdict(name=name, tier=tier, weight=weight, verdict=verdict,
                         confidence=confidence, failed=failed, evidence="")


class ScoreObservableTests(SimpleTestCase):
    def test_tier1_malicious_high_conf_is_dangerous(self):
        v = score_observable([sv("malicious", tier=1, confidence=90), sv("clean", tier=3)])
        self.assertEqual(v.band, "Dangerous")

    def test_tier1_malicious_no_numeric_conf_is_dangerous(self):
        v = score_observable([sv("malicious", tier=1, confidence=None)])
        self.assertEqual(v.band, "Dangerous")

    def test_two_tier2_malicious_is_dangerous(self):
        v = score_observable([sv("malicious", tier=2), sv("malicious", tier=2), sv("clean", tier=3)])
        self.assertEqual(v.band, "Dangerous")

    def test_tier3_only_high_share_still_caps_at_suspicious(self):
        # 3 tier-3 malicious vs 1 tier-3 clean -> share .75, but no trusted source -> capped
        v = score_observable([sv("malicious"), sv("malicious"), sv("malicious"), sv("clean")])
        self.assertEqual(v.band, "Suspicious")

    def test_share_over_half_with_a_trusted_malicious_is_dangerous(self):
        # same share, but one of the malicious voters is tier-2 -> Dangerous
        v = score_observable([sv("malicious", tier=2), sv("malicious"), sv("malicious"), sv("clean")])
        self.assertEqual(v.band, "Dangerous")

    def test_tier3_only_flag_caps_at_suspicious(self):
        v = score_observable([sv("malicious", tier=3), sv("clean", tier=3), sv("clean", tier=3), sv("clean", tier=3)])
        self.assertEqual(v.band, "Suspicious")

    def test_tier1_clean_and_nothing_flags_is_safe(self):
        v = score_observable([sv("clean", tier=1), sv("clean", tier=3)])
        self.assertEqual(v.band, "Safe")

    def test_tier1_clean_but_tier3_flags_is_suspicious_not_safe(self):
        v = score_observable([sv("clean", tier=1), sv("malicious", tier=3)])
        self.assertEqual(v.band, "Suspicious")

    def test_thin_coverage_is_inconclusive(self):
        v = score_observable([sv("clean", tier=3), sv("no-data", tier=1)])
        self.assertEqual(v.band, "Inconclusive")
        self.assertEqual(v.inconclusive_reason, "thin_coverage")

    def test_no_data_sources_do_not_vote(self):
        v = score_observable([sv("clean", tier=1), sv("no-data", tier=2), sv("no-data", tier=3)])
        self.assertEqual(v.band, "Safe")

    def test_failed_tier1_lowers_confidence(self):
        strong = score_observable([sv("clean", tier=1, confidence=100), sv("clean", tier=2, confidence=100)])
        degraded = score_observable([sv("clean", tier=1, confidence=100), sv("no-data", tier=1, failed=True)])
        self.assertLess(degraded.confidence, strong.confidence)

    def test_rationale_non_empty(self):
        v = score_observable([sv("malicious", tier=1, confidence=90, name="GTI")])
        self.assertTrue(any("GTI" in line for line in v.rationale))

    def test_counts(self):
        v = score_observable([sv("malicious"), sv("clean"), sv("clean"), sv("no-data")])
        self.assertEqual(v.counts, {"malicious": 1, "suspicious": 0, "clean": 2, "no-data": 1})

    # --- refinement: Tier-1 clean beats Tier-3 noise (spec §4.2, validated) ---
    def test_tier1_clean_plus_tier3_suspicious_is_safe(self):
        v = score_observable([sv("clean", tier=1), sv("clean", tier=1), sv("suspicious", tier=3)])
        self.assertEqual(v.band, "Safe")

    def test_tier1_clean_plus_tier3_malicious_is_suspicious(self):
        v = score_observable([sv("clean", tier=1), sv("malicious", tier=3)])
        self.assertEqual(v.band, "Suspicious")


def ov(band, confidence=80):
    return ObservableVerdict(band, confidence, None, {}, [])


class ScoreGroupTests(SimpleTestCase):
    def test_worst_of_wins(self):
        g = score_group([ov("Safe"), ov("Suspicious"), ov("Dangerous")])
        self.assertEqual(g.band, "Dangerous")

    def test_inconclusive_ignored_when_others_have_verdict(self):
        g = score_group([ov("Inconclusive"), ov("Safe"), ov("Suspicious")])
        self.assertEqual(g.band, "Suspicious")

    def test_all_inconclusive_is_inconclusive(self):
        g = score_group([ov("Inconclusive"), ov("Inconclusive")])
        self.assertEqual(g.band, "Inconclusive")

    def test_counts_and_rationale(self):
        g = score_group([ov("Dangerous"), ov("Dangerous"), ov("Safe")])
        self.assertEqual(g.counts["Dangerous"], 2)
        self.assertTrue(any("2 of 3" in line for line in g.rationale))

    def test_confidence_is_min_at_worst_band(self):
        g = score_group([ov("Dangerous", 40), ov("Dangerous", 90), ov("Safe", 100)])
        self.assertEqual(g.confidence, 40)
