from django.test import SimpleTestCase

from score_process.scoring.explanation.adapters import _BANDS
from score_process.scoring.narration.verdict_lock import (
    _BAND_WORDS,
    render_fixed_facts,
    validate_narration,
)


class RenderFixedFactsTest(SimpleTestCase):
    def test_includes_all_facts_verbatim(self):
        verdict = {"band": "Dangerous", "score": 9.5, "confidence": 85, "rule": "malicious-count"}
        text = render_fixed_facts(verdict)
        self.assertIn("Dangerous", text)
        self.assertIn("9.5", text)
        self.assertIn("85", text)
        self.assertIn("malicious-count", text)


class ValidateNarrationTest(SimpleTestCase):
    def test_matching_band_passes(self):
        verdict = {"band": "Dangerous", "score": 9.5, "confidence": 85, "rule": "malicious-count"}
        text = "This case is Dangerous. Multiple analyzers flagged the URL as malicious."
        result = validate_narration(text, verdict)
        self.assertTrue(result.passed)
        self.assertEqual(result.reasons, [])

    def test_contradicting_band_fails(self):
        verdict = {"band": "Dangerous", "score": 9.5, "confidence": 85, "rule": "malicious-count"}
        text = "Overall, this case appears Safe and no action is required."
        result = validate_narration(text, verdict)
        self.assertFalse(result.passed)
        self.assertTrue(any("Safe" in r for r in result.reasons))

    def test_no_verdict_language_passes(self):
        verdict = {"band": "Suspicious", "score": 5.0, "confidence": 60, "rule": "weighted-malicious-share"}
        text = "VirusTotal reported 3 of 70 engines flagged this domain. GTI found no prior reputation data."
        result = validate_narration(text, verdict)
        self.assertTrue(result.passed)

    def test_fabricated_confidence_fails(self):
        verdict = {"band": "Dangerous", "score": 9.5, "confidence": 90, "rule": "malicious-count"}
        text = "We are Dangerous with 40% confidence based on the available evidence."
        result = validate_narration(text, verdict)
        self.assertFalse(result.passed)
        self.assertTrue(any("40" in r for r in result.reasons))

    def test_close_confidence_within_tolerance_passes(self):
        verdict = {"band": "Dangerous", "score": 9.5, "confidence": 90, "rule": "malicious-count"}
        text = "This is Dangerous with roughly 88% confidence."
        result = validate_narration(text, verdict)
        self.assertTrue(result.passed)

    def test_negated_contradicting_band_does_not_fail(self):
        verdict = {"band": "Safe", "score": 0.0, "confidence": 90, "rule": "no-malicious-sources"}
        text = "No suspicious indicators were found. Nothing dangerous was detected."
        result = validate_narration(text, verdict)
        self.assertTrue(result.passed)

    def test_negated_band_via_contraction_does_not_fail(self):
        verdict = {"band": "Dangerous", "score": 9.5, "confidence": 85, "rule": "malicious-count"}
        text = "This message is not safe to open; do not click the link."
        result = validate_narration(text, verdict)
        self.assertTrue(result.passed)

    def test_decimal_percentage_parsed_correctly(self):
        verdict = {"band": "Dangerous", "score": 9.5, "confidence": 90, "rule": "malicious-count"}
        text = "This is Dangerous with roughly 88.5% confidence."
        result = validate_narration(text, verdict)
        self.assertTrue(result.passed)

    def test_unrelated_percentage_not_flagged(self):
        verdict = {"band": "Suspicious", "score": 4.8, "confidence": 55, "rule": "group-worst-of"}
        text = "Only about 5% of security engines flagged this domain as suspicious."
        result = validate_narration(text, verdict)
        self.assertTrue(result.passed)

    def test_negation_many_words_before_band_in_same_sentence_does_not_fail(self):
        # Observed on a real Ollama generation: negation and the band word
        # were 59 characters apart, past a fixed-width lookback window.
        verdict = {"band": "Suspicious", "score": 4.8, "confidence": 55, "rule": "group-worst-of"}
        text = (
            "The confidence level of 55 out of 100 indicates that while there "
            "are some red flags, the evidence is not strong enough to "
            "conclusively label the case as highly dangerous."
        )
        result = validate_narration(text, verdict)
        self.assertTrue(result.passed)


class BandWordsPinnedTest(SimpleTestCase):
    def test_band_words_match_canonical_bands(self):
        self.assertEqual(set(_BAND_WORDS), _BANDS)
