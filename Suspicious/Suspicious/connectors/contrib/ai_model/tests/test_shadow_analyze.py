from django.test import TestCase

from ai_model import registry
from ai_model.tests.test_registry import cand
from connectors.contrib.ai_model.tests import test_connector as base
from connectors.contrib.ai_model.tests.test_connector import payload


def with_shadow(shadow, version="s1"):
    p = payload()
    if shadow is not ...:
        p["results"]["shadow"] = shadow
    return p


class ShadowAnalyzeTest(TestCase):
    # AnalyzeTest's fixtures without re-running its tests.
    analyze = base.AnalyzeTest.analyze

    def setUp(self):
        base.AnalyzeTest.setUp(self)
        self.version = cand("s1", manifest={"eligible": True})

    def start_shadow(self):
        registry.set_shadow(self.version)

    def good(self, version="s1"):
        return {"version": version, "class": "DANGEROUS", "score": 9.0, "confidence": 0.8,
                "sub_class": "X", "probabilities": {}}

    def test_without_a_shadow_the_request_is_unchanged(self):
        result, _, call = self.analyze(classify={"return_value": with_shadow(self.good())})
        call.assert_called_once_with("the mail", exclude_case_ids=[self.case.id])
        self.assertIsNone(result.shadow)

    def test_with_a_shadow_both_versions_are_asked_and_the_answer_rides_along(self):
        self.start_shadow()
        plain, _, _ = self.analyze()
        result, _, call = self.analyze(classify={"return_value": with_shadow(self.good())})
        call.assert_called_once_with("the mail", exclude_case_ids=[self.case.id], versions=["active", "shadow"])
        self.assertEqual(result.shadow["class"], "DANGEROUS")
        self.assertEqual(result.shadow, self.good())
        self.assertEqual((result.result, result.score, result.confidence, result.assessment),
                         (plain.result, plain.score, plain.confidence, plain.assessment))

    def test_a_bad_shadow_answer_leaves_the_result_as_without_one(self):
        self.start_shadow()
        plain, _, _ = self.analyze()
        for shadow in ({"error": "Timeout"}, ..., "junk", None):
            result, _, _ = self.analyze(classify={"return_value": with_shadow(shadow)})
            self.assertIsNone(result.shadow)
            self.assertEqual(result, plain)
