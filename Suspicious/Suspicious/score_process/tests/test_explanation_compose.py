import re
from django.test import SimpleTestCase
from score_process.scoring.explanation.compose import compose, RULE_KEYS
from score_process.scoring.explanation.types import SourceLine

FACTS = dict(source="GTI", n_context=2, n_counted=1, n_total=3, share=0.67,
             data_type="url", missing="no authoritative source ran")


class ComposeTest(SimpleTestCase):
    def test_every_rule_key_composes_fully(self):
        for rule in RULE_KEYS:
            a, r, c = compose(rule, "Dangerous", 80, [SourceLine("GTI", 1, "malicious", True, "")], **FACTS)
            for text in (a, r, c):
                self.assertTrue(text.strip(), f"{rule}: empty text")
                self.assertNotRegex(text, r"\{[a-z_]+\}", f"{rule}: unfilled placeholder in {text!r}")

    def test_unknown_rule_is_generic_not_raising(self):
        a, r, c = compose("nonsense-rule", "Suspicious", 50, [], **FACTS)
        self.assertIn("Suspicious", a)

    def test_safe_low_confidence_special_reading(self):
        _, _, c = compose("no-flag", "Safe", 20, [], **FACTS)
        self.assertIn("does not mean", c.lower())

    def test_strong_confidence_reading(self):
        _, _, c = compose("tier1-authoritative-malicious", "Dangerous", 95, [], **FACTS)
        self.assertRegex(c.lower(), r"strong|high")
