from django.contrib.auth import get_user_model
from django.test import TestCase

from case_handler.models import Case, ObservableGroup
from connectors.contrib.ai_narration.adapters import case_to_verdict_dict


class CaseToVerdictDictTest(TestCase):
    def setUp(self):
        reporter = get_user_model().objects.create_user(username="r", password="x")
        group = ObservableGroup.objects.create(label="g")
        self.case = Case.objects.create(
            observable_group=group, reporter=reporter, description="",
            results="Dangerous", final_score=9.2, final_confidence=88,
        )

    def test_uses_decisive_rule_from_verdict_explanation(self):
        self.case.verdict_explanation = {"band": "Dangerous", "confidence": 88, "decisive_rule": "embedded-ioc-escalation"}
        self.case.save(update_fields=["verdict_explanation"])
        result = case_to_verdict_dict(self.case)
        self.assertEqual(result, {
            "band": "Dangerous", "score": 9.2, "confidence": 88, "rule": "embedded-ioc-escalation",
        })

    def test_rule_is_unknown_when_no_verdict_explanation(self):
        result = case_to_verdict_dict(self.case)
        self.assertEqual(result["rule"], "unknown")
        self.assertEqual(result["band"], "Dangerous")
        self.assertEqual(result["score"], 9.2)
        self.assertEqual(result["confidence"], 88)

    def test_raises_on_unknown_band(self):
        self.case.results = "Failure"
        self.case.save(update_fields=["results"])
        with self.assertRaises(ValueError):
            case_to_verdict_dict(self.case)
