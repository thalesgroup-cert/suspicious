from django.test import SimpleTestCase

from score_process.scoring.narration.prompt import build_prompt


class BuildPromptTest(SimpleTestCase):
    def test_includes_fixed_facts_and_reports_and_instructions(self):
        verdict = {"band": "Suspicious", "score": 5.0, "confidence": 60, "rule": "weighted-malicious-share"}
        reports = [
            {"analyzer": "VirusTotal_v3", "report_full": {"positives": 3, "total": 70}},
            {"analyzer": "GTI", "report_full": {"reputation": "unknown"}},
        ]
        prompt = build_prompt(verdict, reports)

        self.assertIn("Suspicious", prompt)
        self.assertIn("VirusTotal_v3", prompt)
        self.assertIn("GTI", prompt)
        self.assertIn("positives", prompt)
        self.assertIn("do not restate them differently", prompt.lower())

    def test_empty_reports_still_produces_valid_prompt(self):
        verdict = {"band": "Safe", "score": 0.0, "confidence": 95, "rule": "no-malicious-sources"}
        prompt = build_prompt(verdict, [])
        self.assertIn("Safe", prompt)
        self.assertIn("ANALYZER REPORTS", prompt)
