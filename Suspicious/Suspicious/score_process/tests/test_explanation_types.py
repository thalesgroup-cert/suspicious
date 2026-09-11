from django.test import SimpleTestCase
from score_process.scoring.explanation.types import SourceLine, VerdictExplanation


class ExplanationTypesTest(SimpleTestCase):
    def _ve(self):
        return VerdictExplanation(
            band="Dangerous", confidence=90, decisive_rule="tier1-authoritative-malicious",
            analyst_paragraph="A.", reporter_paragraph="R.", confidence_reading="C.",
            sources=(SourceLine("GTI", 1, "malicious", True, "trojan"),
                     SourceLine("DShield", 3, "no-data", False, "")),
        )

    def test_to_dict_is_json_safe(self):
        import json
        d = self._ve().to_dict()
        json.dumps(d)  # must not raise
        self.assertEqual(d["band"], "Dangerous")
        self.assertEqual(d["sources"][0], {"name": "GTI", "tier": 1, "verdict": "malicious",
                                           "counted": True, "note": "trojan"})
        self.assertEqual(len(d["sources"]), 2)

    def test_frozen(self):
        with self.assertRaises(Exception):
            self._ve().band = "Safe"
