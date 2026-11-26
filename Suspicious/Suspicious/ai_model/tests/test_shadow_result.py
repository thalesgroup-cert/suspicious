from unittest import mock

from django.test import TestCase, TransactionTestCase

from ai_model import registry
from ai_model.models import AiAssessment, ModelVersion, ShadowResult
from ai_model.tests.test_registry import cand
from connectors.contrib.ai_model.connector import AiModelConnector, _result, to_fetch_result
from connectors.contrib.ai_model.tests.test_connector import make_mail_case
from connectors.tasks import run_engine_job
from cortex_job.cortex_utils.cortex_and_job_management import ai_analyzer_name
from cortex_job.models import Analyzer, CaseAnalyzerJob


def answer(version, klass="SAFE", confidence=0.9):
    return {"version": version, "class": klass, "score": 2.4, "confidence": confidence,
            "sub_class": "HAM", "probabilities": {"SAFE": "90.00%"}, "tier": None}


def live(shadow):
    return _result("SAFE", 2, 90, "Ham", "v0", {"sub_class": "HAM"}, shadow=shadow)


def finish_job(case, result) -> bool:
    """A pending ai_model row closed by run_engine_job with ``result``; True when it succeeded."""
    analyzer, _ = Analyzer.objects.get_or_create(
        name=ai_analyzer_name(), defaults={"analyzer_cortex_id": "ai_model:mail_classifier", "source": "ai_model"})
    row = CaseAnalyzerJob.objects.create(case=case, cortex_job_id=f"ai_model-{CaseAnalyzerJob.objects.count()}",
                                         analyzer=analyzer, status=CaseAnalyzerJob.STATUS_INPROGRESS)
    with mock.patch.object(AiModelConnector, "run", return_value=to_fetch_result(result)):
        run_engine_job.apply(args=(row.id,))
    row.refresh_from_db()
    return row.status == CaseAnalyzerJob.STATUS_SUCCESS


class ShadowResultTest(TestCase):
    def setUp(self):
        self.case, _ = make_mail_case()
        self.version = cand("s1", manifest={"eligible": True})
        registry.set_shadow(self.version)

    def finish(self, result):
        with self.captureOnCommitCallbacks(execute=False):
            return finish_job(self.case, result)

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
                self.assertLogs("connectors.contrib.ai_model", "WARNING") as logs:
            self.assertTrue(self.finish(live(answer("s1"))))
        self.assertIn("RuntimeError", "".join(logs.output))
        self.assertNotIn("secret", "".join(logs.output))
        self.assertEqual(AiAssessment.objects.get().result, "SAFE")
        self.assertEqual(CaseAnalyzerJob.objects.get().status, CaseAnalyzerJob.STATUS_SUCCESS)

    def test_a_database_error_in_the_store_leaves_the_live_analysis_written(self):
        def broken(*args, **kwargs):  # an ORM write failing inside the live transaction
            ModelVersion.objects.create(version_id="s1", status="candidate", manifest={},
                                        campaign_profile={}, trigger="manual")

        with mock.patch("ai_model.shadow.store_shadow_result", side_effect=broken), \
                self.assertLogs("connectors.contrib.ai_model", "WARNING") as logs:
            self.assertTrue(self.finish(live(answer("s1"))))
        self.assertIn("IntegrityError", "".join(logs.output))
        self.assertEqual(AiAssessment.objects.get().result, "SAFE")
        self.assertEqual(CaseAnalyzerJob.objects.get().status, CaseAnalyzerJob.STATUS_SUCCESS)

    def test_a_malformed_answer_is_not_raised(self):
        self.assertTrue(self.finish(live({"version": "s1"})))
        self.assertFalse(ShadowResult.objects.exists())


class ShadowStoredBeforeReconcileTest(TransactionTestCase):
    """Real commits: reconcile (get_report, record_would_be) must find the shadow row."""

    def test_the_row_exists_when_reconcile_is_queued(self):
        case, _ = make_mail_case()
        with mock.patch("ai_model.registry._queue_seeding"):
            registry.set_shadow(cand("s1", manifest={"eligible": True}))
        seen = []
        with mock.patch("tasp.tasks.reconcile_case") as reconcile:
            reconcile.delay.side_effect = lambda *a: seen.append(ShadowResult.objects.exists())
            self.assertTrue(finish_job(case, live(answer("s1"))))
        self.assertEqual(seen, [True])
