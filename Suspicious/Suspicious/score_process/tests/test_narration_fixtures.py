import json
from pathlib import Path

from django.test import SimpleTestCase

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "narration"
FIXTURE_NAMES = [
    "mail_safe.json",
    "mail_suspicious.json",
    "mail_dangerous.json",
    "ioc_safe.json",
    "ioc_suspicious_multi.json",
    "ioc_dangerous_single.json",
]


class FixtureShapeTest(SimpleTestCase):
    def test_all_fixtures_exist_and_have_required_shape(self):
        for name in FIXTURE_NAMES:
            path = FIXTURES_DIR / name
            with self.subTest(fixture=name):
                self.assertTrue(path.exists(), f"missing fixture {path}")
                data = json.loads(path.read_text())
                self.assertIn("verdict", data)
                verdict = data["verdict"]
                for key in ("band", "score", "confidence", "rule"):
                    self.assertIn(key, verdict)
                self.assertIn(verdict["band"], ("Safe", "Suspicious", "Dangerous", "Inconclusive"))
                self.assertIn("analyzer_reports", data)
                for report in data["analyzer_reports"]:
                    self.assertIn("analyzer", report)
                    self.assertIn("report_full", report)
