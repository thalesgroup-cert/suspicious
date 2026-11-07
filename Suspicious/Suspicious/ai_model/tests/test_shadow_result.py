from unittest import mock

from django.test import TestCase

from ai_model import registry
from ai_model.models import AiAssessment, ModelVersion, ShadowResult
from ai_model.tests.test_registry import cand
from connectors.base import ProviderResult
from connectors.providers import finish_provider_analysis, queue_provider_analysis
from connectors.tests.test_provider_dispatch import make_mail_case


def answer(version, klass="SAFE", confidence=0.9):
    return {"version": version, "class": klass, "score": 2.4, "confidence": confidence,
            "sub_class": "HAM", "probabilities": {"SAFE": "90.00%"}, "tier": None}


def live(shadow):
    return ProviderResult("SAFE", 2, 90, "Ham", "v0", {"sub_class": "HAM"}, shadow=shadow)


class ShadowResultTest(TestCase):
    def setUp(self):
        self.case, _ = make_mail_case()
        self.version = cand("s1", manifest={"eligible": True})
        registry.set_shadow(self.version)

    def finish(self, result):
        with mock.patch("connectors.providers.enabled_provider", return_value="ai_model"):
            job = queue_provider_analysis(self.case, "mail_ai")
        with self.captureOnCommitCallbacks(execute=False):
            return finish_provider_analysis(job.id, result, connector="ai_model")

    def test_a_good_answer_is_stored_as_live_and_the_live_side_is_unchanged(self):
        self.assertTrue(self.finish(live(answer("s1", "INCONCLUSIVE", 3.0))))
        row = ShadowResult.objects.get()
        self.assertEqual((row.case, row.version, row.origin, row.result, row.score, row.confidence),
                         (self.case, self.version, "live", "INCONCLUSIVE", 2, 100))
        self.assertEqual(row.live_result, "")
        self.assertEqual(AiAssessment.objects.get().result, "SAFE")
        self.case.refresh_from_db()
        self.assertEqual((self.case.results_ai, self.case.score_ai), ("Safe", 2))

    def test_no_shadow_or_another_version_stores_nothing(self):
        self.finish(live(None))
        self.assertFalse(ShadowResult.objects.exists())

    def test_an_answer_for_another_version_is_dropped(self):
        self.finish(live(answer("old")))
        self.assertFalse(ShadowResult.objects.exists())

    def test_a_redo_overwrites_the_row(self):
        self.finish(live(answer("s1", "SAFE")))
        self.finish(live(answer("s1", "DANGEROUS")))
        self.assertEqual(list(ShadowResult.objects.values_list("result", flat=True)), ["DANGEROUS"])

    def test_a_store_failure_is_logged_by_class_and_not_raised(self):
        with mock.patch("ai_model.shadow.store_shadow_result", side_effect=RuntimeError("secret mail")), \
                self.assertLogs("connectors.delivery", "WARNING") as logs:
            self.assertTrue(self.finish(live(answer("s1"))))
        self.assertIn("RuntimeError", "".join(logs.output))
        self.assertNotIn("secret", "".join(logs.output))
        self.assertEqual(AiAssessment.objects.get().result, "SAFE")

    def test_a_malformed_answer_is_not_raised(self):
        self.assertTrue(self.finish(live({"version": "s1"})))
        self.assertFalse(ShadowResult.objects.exists())
