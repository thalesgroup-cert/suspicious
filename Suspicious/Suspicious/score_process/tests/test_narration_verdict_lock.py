from django.test import SimpleTestCase

from score_process.scoring.narration.verdict_lock import (
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
