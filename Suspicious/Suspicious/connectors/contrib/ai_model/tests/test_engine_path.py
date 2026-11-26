"""Parity suite: the mail AI verdict as an analysis-engine job (dispatch_mail_ai, run_engine_job,
AiModelConnector.run/on_started/on_result) writes what the retired mail_ai provider path wrote.

Ported from the deleted connectors/tests/test_provider_dispatch.py and the ai_model provider tests,
with the same assertions on the case fields, AiAssessment, ledger rows and delivery rows."""
from datetime import timedelta
from unittest import mock

import pybreaker
from celery.exceptions import Retry
from django.test import TestCase
from django.utils import timezone

from ai_model import registry as model_registry
from ai_model.mailinfo import dispatch_mail_ai, has_assessment, mark_ai_missing
from ai_model.models import AiAssessment, ShadowResult
from ai_model.tests.test_registry import cand
from case_handler.lifecycle import LifecycleState
from case_handler.models import Case, Result
from common.http_client import BREAKERS
from common.storage import FakeObjectStore
from connectors.base import (
    DATA_TYPE_MAIL_ARCHIVE,
    FETCH_RESULT,
    PROVIDER_KIND_ANALYSIS,
    CatalogEntry,
)
from connectors.contrib.ai_model import connector as module
from connectors.contrib.ai_model import mailtext
from connectors.contrib.ai_model.connector import AiModelConnector
from connectors.contrib.ai_model.tests.test_connector import CONFIG, make_mail_case, payload
from connectors.contrib.cortex.connector import CortexConnector
from connectors.models import ConnectorDelivery, ConnectorState
from connectors.providers import ProviderUnavailable
from connectors.registry import ConnectorRegistry
from connectors.tasks import run_engine_job
from cortex_job.cortex_utils.cortex_and_job_management import CortexJobManager, ai_analyzer_name
from cortex_job.cortex_utils.reconciliation import reconcile_case_core
from cortex_job.models import Analyzer, AnalyzerReport, CaseAnalyzerJob
from mail_feeder.models import MailArchive, MailBody, MailInfo
from score_process.scoring.collect import collect_signals, collect_votes
from tasp.tasks import dispatch_case_analysis

DANGEROUS = payload("DANGEROUS", 7.4, 0.815, "CLASSIC_PHISHING")
DANGEROUS_FIELDS = ("Dangerous", 7, 82, "Classic_phishing")
SAFE = payload("SAFE", 1.0, 0.95, "HAM")
SAFE_FIELDS = ("Safe", 1, 95, "Ham")


class EnginePathMixin:
    """A private registry with the real AiModelConnector (and optionally Cortex); the archive read
    and the HTTP call are stubbed per test through ``self.body`` and ``self.classify``."""

    engines = (AiModelConnector,)

    def setUp(self):
        self.breaker = pybreaker.CircuitBreaker(fail_max=5, reset_timeout=60)
        patcher = mock.patch.dict(BREAKERS, {"ai_model": self.breaker})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.registry = ConnectorRegistry()
        for cls in self.engines:
            self.registry.register(cls)
        for target in ("connectors.engines.registry", "connectors.delivery.registry",
                       "connectors.dispatch.registry", "connectors.registry.registry"):
            patcher = mock.patch(target, self.registry)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch.object(self.registry, "instantiate", side_effect=self.instantiate)
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch("tasp.tasks.reconcile_case")
        self.reconcile = patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch.object(mailtext, "get_store", return_value=FakeObjectStore())
        patcher.start()
        self.addCleanup(patcher.stop)
        self.body = "the mail"
        patcher = mock.patch.object(module, "read_archive_body", side_effect=lambda archive: self.body)
        self.read = patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch.object(module.AiInferenceClient, "classify", return_value=DANGEROUS)
        self.classify = patcher.start()
        self.addCleanup(patcher.stop)
        ConnectorState.objects.create(name="ai_model", enabled=True)
        self.case, self.archive = make_mail_case()

    def instantiate(self, name):
        return AiModelConnector(CONFIG)

    def dispatch(self, case=None):
        case = case or self.case
        with mock.patch("connectors.tasks.run_engine_job.delay") as delay, \
                self.captureOnCommitCallbacks(execute=True):
            ids = dispatch_mail_ai(case)
        self.delay = delay
        return ids

    def queue(self):
        """dispatch_mail_ai, returning the row it wrote (as queue_provider_analysis returned it)."""
        ids = self.dispatch()
        self.assertEqual(len(ids), 1)
        return CaseAnalyzerJob.objects.get(cortex_job_id=ids[0])

    def run_task(self, row, retries=0):
        with self.captureOnCommitCallbacks(execute=True):
            run_engine_job.apply(args=(row.id,), retries=retries)
        row.refresh_from_db()
        self.case.refresh_from_db()
        return row

    def ai_fields(self, case=None):
        case = case or self.case
        case.refresh_from_db()
        return (case.results_ai, case.score_ai, case.confidence_ai, case.category_ai)


class EnginePathTest(EnginePathMixin, TestCase):
    def assert_failed(self, row, text):
        self.assertEqual(row.status, CaseAnalyzerJob.STATUS_FAILURE)
        self.assertIsNotNone(row.completed_at)
        self.assertEqual(self.case.results_ai, "Inconclusive")
        delivery = ConnectorDelivery.objects.get()
        self.assertEqual((delivery.connector, delivery.event, delivery.status), ("ai_model", "analyze", "failed"))
        self.assertIn(text, delivery.error)
        self.reconcile.delay.assert_called_once_with(self.case.id)

    def assert_no_answer(self, row, text):
        self.assert_failed(row, text)
        defaults = {name: Case._meta.get_field(name).get_default()
                    for name in ("score_ai", "confidence_ai", "category_ai")}
        self.assertEqual(defaults["category_ai"], "Uncategorized")  # what the dashboard counts
        self.assertEqual({name: getattr(self.case, name) for name in defaults}, defaults)
        self.assertFalse(AiAssessment.objects.exists())
        self.assertFalse(MailInfo.objects.get(mail=self.archive.mail).is_analyzed)

    # ── the connector's engine contract ─────────────────────────────────────

    def test_the_connector_is_a_mail_only_analysis_engine(self):
        self.assertEqual(AiModelConnector.manifest.provides, PROVIDER_KIND_ANALYSIS)
        self.assertIs(AiModelConnector.general_purpose, False)
        entry = CatalogEntry("mail_classifier", ai_analyzer_name(), (DATA_TYPE_MAIL_ARCHIVE,))
        connector = AiModelConnector(CONFIG)
        self.assertEqual(connector.catalog(name=ai_analyzer_name()), [entry])
        self.assertEqual(connector.catalog(data_type=DATA_TYPE_MAIL_ARCHIVE), [entry])
        for query in ({}, {"name": "Yara_2_0"}, {"data_type": "url"}, {"data_type": "file"}):
            self.assertEqual(connector.catalog(**query), [], query)

    def test_start_defers_and_refuses_a_blank_value(self):
        connector = AiModelConnector(CONFIG)
        entry = connector.catalog(name=ai_analyzer_name())[0]
        started = connector.start(entry, DATA_TYPE_MAIL_ARCHIVE, "12")
        self.assertIs(started.deferred, True)
        self.assertEqual(len(started.job_id), 24)
        self.assertNotEqual(started.job_id, connector.start(entry, DATA_TYPE_MAIL_ARCHIVE, "12").job_id)
        self.assertIsNone(connector.start(entry, DATA_TYPE_MAIL_ARCHIVE, ""))

    # ── dispatch ────────────────────────────────────────────────────────────

    def test_dispatch_creates_a_pending_reportless_row_for_the_ai_analyzer(self):
        row = self.queue()
        self.assertEqual((row.status, row.analyzer.name, row.analyzer.source),
                         ("InProgress", ai_analyzer_name(), "ai_model"))
        self.assertTrue(row.cortex_job_id.startswith("ai_model-"))
        self.assertIsNone(row.analyzer_report)
        self.assertFalse(AnalyzerReport.objects.exists())
        self.delay.assert_called_once_with(row.id)

    def test_dispatch_reuses_the_configured_ai_analyzer_and_its_weight(self):
        existing = Analyzer.objects.create(name=ai_analyzer_name(), analyzer_cortex_id="provider:x",
                                           source="ai_model", weight=0.7)
        row = self.queue()
        self.assertEqual(row.analyzer, existing)
        existing.refresh_from_db()
        self.assertEqual(existing.weight, 0.7)

    def test_on_started_marks_the_ai_missing_at_registration(self):
        self.assertEqual(self.case.results_ai, "Suspicious")  # the model default
        self.queue()
        self.case.refresh_from_db()
        self.assertEqual(self.case.results_ai, "Inconclusive")

    def test_dispatch_without_an_engine_offering_the_role_marks_the_ai_missing(self):
        ConnectorState.objects.filter(name="ai_model").update(enabled=False)
        self.assertEqual(self.dispatch(), [])
        self.assertFalse(CaseAnalyzerJob.objects.exists())
        self.case.refresh_from_db()
        self.assertEqual(self.case.results_ai, "Inconclusive")
        self.assertIs(collect_signals(self.case)[3], True)

    def test_a_refused_start_marks_the_ai_missing(self):
        with mock.patch.object(AiModelConnector, "start", return_value=None):
            self.assertEqual(self.dispatch(), [])
        self.case.refresh_from_db()
        self.assertEqual(self.case.results_ai, "Inconclusive")

    def test_the_path_and_the_vote_work_without_analyzers_ai(self):
        with mock.patch(
            "cortex_job.cortex_utils.cortex_and_job_management._get_cortex_config",
            return_value={"analyzers": {"yara": "Yara_2_0"}},
        ):
            row = self.run_task(self.queue())
            ai = collect_signals(self.case)[1]
            votes = {v.analyzer: v for v in collect_votes(self.case, ai)}
        self.assertEqual(row.analyzer.name, "AI_Mail_Analyzer")
        self.assertEqual(row.status, CaseAnalyzerJob.STATUS_SUCCESS)
        self.assertEqual(self.case.results_ai, "Dangerous")
        self.assertEqual(votes["AI_Mail_Analyzer"].weight, 0.2)  # the row's default weight

    # ── a normal answer ─────────────────────────────────────────────────────

    def test_a_server_answer_writes_case_fields_assessment_and_closes_the_row(self):
        row = self.run_task(self.queue())
        self.classify.assert_called_once_with("the mail", exclude_case_ids=[self.case.id])
        self.assertEqual(self.ai_fields(), DANGEROUS_FIELDS)
        a = AiAssessment.objects.get(case=self.case)
        self.assertEqual((a.model_version, a.result, a.sub_class, a.score, a.confidence),
                         ("v0", "DANGEROUS", "CLASSIC_PHISHING", 7, 82))
        self.assertEqual((a.probabilities, a.sub_probabilities, a.contributing_phrases, a.tier,
                          a.campaign_embedding, a.embedding_version, a.latency_ms),
                         (DANGEROUS["results"]["active"]["probabilities"],
                          {"CLASSIC_PHISHING": "70.00%"}, [["verify", 0.3]], "", "[0.1, 0.2]", "cmp-e1", 12))
        self.assertEqual(row.status, CaseAnalyzerJob.STATUS_SUCCESS)
        self.assertIsNotNone(row.completed_at)
        info = MailInfo.objects.get(mail=self.archive.mail)
        self.assertEqual((info.is_analyzed, info.is_phishing, info.is_dangerous), (True, True, True))
        delivery = ConnectorDelivery.objects.get()
        self.assertEqual(
            (delivery.connector, delivery.event, delivery.status, delivery.case_id, delivery.error,
             delivery.attempt),
            ("ai_model", "analyze", "success", self.case.id, "", 1),
        )
        self.reconcile.delay.assert_called_once_with(self.case.id)

    def test_every_assessment_field_is_reset_to_its_default_then_the_results(self):
        AiAssessment.objects.create(
            case=self.case, model_version="old", result="SAFE", score=1, confidence=1, tier="T9",
            similar_cases=[1], contributing_phrases=[["x", 1]], campaign_embedding="[9]",
            embedding_version="old-e", latency_ms=99, sub_class="OLD", probabilities={"a": 1},
        )
        sparse = {"result": "SAFE", "score": 2, "confidence": 90, "category": "Ham",
                  "model_version": "v0", "assessment": {"sub_class": "HAM"}, "reason": "", "shadow": None}
        with mock.patch.object(module, "result_from_server", return_value=sparse):
            self.run_task(self.queue())
        a = AiAssessment.objects.get(case=self.case)
        self.assertEqual(
            (a.model_version, a.result, a.score, a.confidence, a.sub_class, a.tier, a.similar_cases,
             a.contributing_phrases, a.campaign_embedding, a.embedding_version, a.latency_ms,
             a.probabilities, a.sub_probabilities),
            ("v0", "SAFE", 2, 90, "HAM", "", [], [], "", "cmp-e1", 0, {}, {}),
        )

    def test_a_model_inconclusive_class_with_a_version_is_a_success(self):
        self.classify.return_value = payload("INCONCLUSIVE", 3.0, 0.45, "CLONE")
        row = self.run_task(self.queue())
        self.assertEqual(row.status, CaseAnalyzerJob.STATUS_SUCCESS)
        self.assertEqual(self.ai_fields(), ("Inconclusive", 3, 45, "Clone"))
        self.assertEqual(AiAssessment.objects.get().result, "INCONCLUSIVE")
        info = MailInfo.objects.get(mail=self.archive.mail)
        self.assertEqual((info.is_analyzed, info.is_phishing, info.is_dangerous), (True, True, False))
        self.assertEqual(ConnectorDelivery.objects.get().status, "success")

    def test_a_long_category_is_cut_to_the_case_column(self):
        self.classify.return_value = payload(sub_class="x" * 80)
        self.run_task(self.queue())
        self.assertEqual(len(self.case.category_ai), 20)

    # ── no answer: Failure, AI missing ──────────────────────────────────────

    def test_no_archive_is_a_failure_with_its_reason(self):
        MailArchive.objects.all().delete()
        self.assert_no_answer(self.run_task(self.queue()), "no model_version (no_mail_archive)")
        self.read.assert_not_called()
        self.classify.assert_not_called()

    def test_an_unreadable_archive_is_a_failure_with_its_reason(self):
        self.body = None
        self.assert_no_answer(self.run_task(self.queue()), "no model_version (archive_unreadable)")
        self.classify.assert_not_called()

    def test_a_server_refusal_is_a_failure_and_never_trips_the_breaker(self):
        self.breaker = BREAKERS["ai_model"] = pybreaker.CircuitBreaker(fail_max=1, reset_timeout=60)
        self.classify.side_effect = ValueError("HTTP 422: bad body")
        with self.assertLogs("connectors", "WARNING") as logs:
            row = self.run_task(self.queue())
        self.assert_no_answer(row, "no model_version (HTTP 422: bad body)")
        self.assertTrue(any("provider failed" in line and "HTTP 422" in line for line in logs.output))
        self.assertEqual(self.breaker.current_state, "closed")

    def test_an_answer_without_a_model_version_is_a_failure(self):
        answer = payload()
        answer["results"]["active"]["version"] = ""
        self.classify.return_value = answer
        self.assert_no_answer(self.run_task(self.queue()), "no model_version")

    def test_the_run_payload_carries_what_the_provider_result_carried(self):
        result = AiModelConnector(CONFIG).run("x", DATA_TYPE_MAIL_ARCHIVE, str(self.case.id))
        self.assertEqual((result.state, result.status), (FETCH_RESULT, "Success"))
        self.assertEqual(set(result.payload), {"result", "score", "confidence", "category",
                                               "model_version", "assessment", "shadow", "reason"})
        # Same values as the ProviderResult the old path built from the same answer.
        self.assertEqual({k: result.payload[k] for k in ("result", "score", "confidence", "category",
                                                         "model_version", "reason", "shadow")},
                         {"result": "DANGEROUS", "score": 7, "confidence": 82, "category": "Classic_phishing",
                          "model_version": "v0", "reason": "", "shadow": None})

    # ── errors ──────────────────────────────────────────────────────────────

    def test_unavailable_after_retries_marks_inconclusive_and_the_row_failed(self):
        row = self.queue()
        self.classify.side_effect = ProviderUnavailable("server down")
        with mock.patch.object(run_engine_job, "retry", wraps=run_engine_job.retry) as retry:
            for retries in (0, 1):  # eager mode propagates Retry: redeliver by hand
                with self.assertRaises(Retry):
                    self.run_task(row, retries)
                row.refresh_from_db()
                self.assertEqual(row.status, CaseAnalyzerJob.STATUS_INPROGRESS)
            row = self.run_task(row, retries=2)
        self.assertEqual(self.classify.call_count, 3)
        first, second = (c.kwargs["countdown"] for c in retry.call_args_list)
        self.assertTrue(5 <= first <= 8 and 10 <= second <= 13, (first, second))
        self.assert_failed(row, "server down")
        self.assertEqual(ConnectorDelivery.objects.get().attempt, 3)
        self.assertFalse(AiAssessment.objects.exists())

    def test_not_retryable_unavailable_fails_without_retrying(self):
        self.classify.side_effect = ProviderUnavailable("model not ready", retryable=False)
        with mock.patch.object(run_engine_job, "retry") as retry:
            row = self.run_task(self.queue())
        retry.assert_not_called()
        self.assert_failed(row, "model not ready")

    def test_other_errors_fail_without_retrying(self):
        self.classify.return_value = payload(score="abc")  # a ValueError outside the HTTP call
        with mock.patch.object(run_engine_job, "retry") as retry:
            row = self.run_task(self.queue())
        retry.assert_not_called()
        self.assert_failed(row, "ValueError")

    def test_a_result_that_cannot_be_stored_closes_the_row_as_failure(self):
        bad = {"result": "SAFE", "score": 0, "confidence": 90, "category": "Ham", "model_version": "v0",
               "assessment": {"nope": 1}, "reason": "", "shadow": None}
        with mock.patch.object(module, "result_from_server", return_value=bad):
            row = self.run_task(self.queue())
        self.assert_failed(row, "could not store the result")
        self.assertFalse(AiAssessment.objects.exists())
        self.assertFalse(MailInfo.objects.get(mail=self.archive.mail).is_analyzed)

    def test_open_breaker_fails_fast(self):
        self.breaker.open()
        row = self.run_task(self.queue())
        self.classify.assert_not_called()
        self.assert_failed(row, "CircuitBreakerError")

    def test_a_connector_disabled_after_the_start_still_finishes_its_job(self):
        # The engine rule (the spec's one parity change): a started job finishes.
        row = self.queue()
        ConnectorState.objects.filter(name="ai_model").update(enabled=False)
        row = self.run_task(row)
        self.assertEqual(row.status, CaseAnalyzerJob.STATUS_SUCCESS)
        self.assertEqual(self.ai_fields(), DANGEROUS_FIELDS)

    def test_redelivery_of_a_closed_job_is_a_no_op(self):
        row = self.queue()
        self.run_task(row)
        AiAssessment.objects.update(tier="kept")
        self.run_task(row)
        self.assertEqual(self.classify.call_count, 1)
        self.assertEqual(ConnectorDelivery.objects.count(), 1)
        self.assertEqual(AiAssessment.objects.get().tier, "kept")
        self.reconcile.delay.assert_called_once_with(self.case.id)

    # ── a second row for one case ───────────────────────────────────────────

    def test_a_second_successful_row_replaces_the_earlier_rows_case_fields(self):
        self.run_task(self.queue())
        self.classify.return_value = SAFE
        self.run_task(self.queue())
        self.assertEqual(self.ai_fields(), SAFE_FIELDS)
        self.assertEqual(AiAssessment.objects.get(case=self.case).result, "SAFE")

    def test_the_case_fields_follow_the_latest_finished_row_not_the_latest_queued(self):
        first, second = self.queue(), self.queue()
        self.classify.return_value = SAFE
        self.run_task(second)
        self.classify.return_value = DANGEROUS
        self.run_task(first)
        self.assertEqual(self.ai_fields(), DANGEROUS_FIELDS)
        self.assertEqual(AiAssessment.objects.get(case=self.case).result, "DANGEROUS")

    def test_a_pending_second_row_keeps_the_earlier_rows_case_fields(self):
        self.run_task(self.queue())
        self.queue()  # on_started does not mark the AI missing: an assessment exists
        self.assertEqual(self.ai_fields(), DANGEROUS_FIELDS)

    def assert_earlier_success_kept(self, row):
        self.assertEqual(row.status, CaseAnalyzerJob.STATUS_FAILURE)
        self.assertEqual(self.ai_fields(), DANGEROUS_FIELDS)
        a = AiAssessment.objects.get(case=self.case)
        self.assertEqual((a.model_version, a.result, a.sub_class), ("v0", "DANGEROUS", "CLASSIC_PHISHING"))

    def test_a_failed_second_row_keeps_the_earlier_rows_assessment_and_case_fields(self):
        self.run_task(self.queue())
        self.classify.side_effect = ProviderUnavailable("model not ready", retryable=False)
        self.assert_earlier_success_kept(self.run_task(self.queue()))

    def test_a_refused_second_row_keeps_the_earlier_rows_assessment_and_case_fields(self):
        self.run_task(self.queue())
        self.classify.side_effect = ValueError("HTTP 400")
        self.assert_earlier_success_kept(self.run_task(self.queue()))

    def test_a_no_archive_second_row_keeps_the_earlier_rows_assessment_and_case_fields(self):
        self.run_task(self.queue())
        MailArchive.objects.all().delete()
        self.assert_earlier_success_kept(self.run_task(self.queue()))

    def test_a_stale_failed_second_row_keeps_the_earlier_rows_case_fields(self):
        from tasp.tasks import fail_stale_jobs

        self.run_task(self.queue())
        row = self.queue()
        CaseAnalyzerJob.objects.filter(pk=row.pk).update(created_at=timezone.now() - timedelta(days=2))
        fail_stale_jobs.apply().get()
        row.refresh_from_db()
        self.assert_earlier_success_kept(row)

    # ── shadow ──────────────────────────────────────────────────────────────

    def shadow_answer(self, version="s1", klass="INCONCLUSIVE"):
        answer = payload()
        answer["results"]["shadow"] = {"version": version, "class": klass, "score": 2.4, "confidence": 3.0,
                                       "sub_class": "HAM", "probabilities": {}, "tier": None}
        return answer

    def test_a_shadow_answer_is_stored_beside_the_live_result(self):
        version = cand("s1", manifest={"eligible": True})
        model_registry.set_shadow(version)
        self.classify.return_value = self.shadow_answer()
        row = self.run_task(self.queue())
        self.classify.assert_called_once_with("the mail", exclude_case_ids=[self.case.id],
                                              versions=["active", "shadow"])
        shadow = ShadowResult.objects.get()
        self.assertEqual((shadow.case, shadow.version, shadow.origin, shadow.result),
                         (self.case, version, "live", "INCONCLUSIVE"))
        self.assertEqual(row.status, CaseAnalyzerJob.STATUS_SUCCESS)
        self.assertEqual(AiAssessment.objects.get().result, "SAFE")
        self.assertEqual(self.ai_fields(), ("Safe", 2, 90, "Ham"))

    def test_a_shadow_store_failure_never_touches_the_live_case(self):
        model_registry.set_shadow(cand("s1", manifest={"eligible": True}))
        self.classify.return_value = self.shadow_answer()
        with mock.patch("ai_model.shadow.store_shadow_result", side_effect=RuntimeError("secret mail")), \
                self.assertLogs("connectors.contrib.ai_model", "WARNING") as logs:
            row = self.run_task(self.queue())
        self.assertIn("RuntimeError", "".join(logs.output))
        self.assertNotIn("secret", "".join(logs.output))
        self.assertEqual(row.status, CaseAnalyzerJob.STATUS_SUCCESS)
        self.assertEqual(AiAssessment.objects.get().result, "SAFE")
        self.assertEqual(self.ai_fields(), ("Safe", 2, 90, "Ham"))
        self.assertEqual(ConnectorDelivery.objects.get().status, "success")

    # ── rows closed without a result ────────────────────────────────────────

    def test_a_row_failed_by_fail_stale_jobs_leaves_the_ai_inconclusive(self):
        from tasp.tasks import fail_stale_jobs

        row = self.queue()
        CaseAnalyzerJob.objects.filter(pk=row.pk).update(created_at=timezone.now() - timedelta(days=2))
        fail_stale_jobs.apply().get()
        row.refresh_from_db()
        self.case.refresh_from_db()
        self.assertEqual(row.status, CaseAnalyzerJob.STATUS_FAILURE)
        self.assertEqual(self.case.results_ai, "Inconclusive")
        # The task redelivered after the close changes nothing.
        self.run_task(row)
        self.classify.assert_not_called()
        self.assertEqual(self.case.results_ai, "Inconclusive")
        self.assertFalse(ConnectorDelivery.objects.exists())

    def test_a_failed_enqueue_leaves_the_ai_inconclusive(self):
        with mock.patch.object(run_engine_job, "apply_async", side_effect=RuntimeError("broker down")), \
                self.assertRaises(RuntimeError), self.captureOnCommitCallbacks(execute=True):
            dispatch_mail_ai(self.case)
        self.case.refresh_from_db()
        self.assertTrue(CaseAnalyzerJob.objects.filter(case=self.case).exists())
        self.assertEqual(self.case.results_ai, "Inconclusive")

    # ── reconcile ───────────────────────────────────────────────────────────

    @mock.patch("cortex_job.cortex_utils.reconciliation.emit_connector_event")
    @mock.patch("cortex_job.cortex_utils.reconciliation.finalise")
    def test_reconcile_waits_for_the_row_then_finalises(self, finalise, *_):
        for answer in (DANGEROUS, ValueError("refused")):
            with self.subTest(answer=answer):
                case, _ = make_mail_case(n=10 + finalise.call_count)
                self.case = case
                setattr(self.classify, "side_effect" if isinstance(answer, Exception) else "return_value", answer)
                row = self.queue()
                reconcile_case_core(case)
                case.refresh_from_db()
                self.assertEqual(case.lifecycle_state, LifecycleState.ANALYZING)
                calls = finalise.call_count
                self.run_task(row)
                reconcile_case_core(case)
                case.refresh_from_db()
                self.assertEqual(case.lifecycle_state, LifecycleState.FINALIZED)
                self.assertEqual(finalise.call_count, calls + 1)

    @mock.patch("cortex_job.cortex_utils.reconciliation.emit_connector_event")
    def test_a_job_finishing_mid_reconcile_keeps_its_fields(self, *_):
        row = self.queue()
        stale = Case.objects.get(pk=self.case.pk)  # reconcile_case loads it before the ledger sync
        with mock.patch.object(CortexJobManager, "update_single_job",
                               side_effect=lambda caj: run_engine_job.apply(args=(row.id,))):
            reconcile_case_core(stale)  # finalise is NOT mocked: it scores and saves the case
        self.case.refresh_from_db()
        self.assertEqual(self.case.lifecycle_state, LifecycleState.FINALIZED)
        self.assertEqual(self.ai_fields(), DANGEROUS_FIELDS)


class AiMissingHelpersTest(TestCase):
    def test_mark_ai_missing_and_has_assessment(self):
        case, _ = make_mail_case()
        self.assertFalse(has_assessment(case))
        mark_ai_missing(case)
        case.refresh_from_db()
        self.assertEqual(case.results_ai, "Inconclusive")
        AiAssessment.objects.create(case=case, model_version="", result="SAFE", score=0, confidence=0)
        self.assertFalse(has_assessment(case))  # a row without a model version is no answer
        AiAssessment.objects.filter(case=case).update(model_version="v0")
        self.assertTrue(has_assessment(case))


class EndToEndParityTest(EnginePathMixin, TestCase):
    """Cortex and ai_model enabled: dispatch_case_analysis's AI intent goes through the real
    engines.dispatch, run_engine_job and reconcile_case_core; the verdict equals the one the old
    provider path gives for the same server answer."""

    engines = (AiModelConnector, CortexConnector)

    def setUp(self):
        super().setUp()
        ConnectorState.objects.create(name="cortex", enabled=True)
        self.cortex = mock.Mock()
        # A Cortex analyzer named like the AI role, not declaring mail_archive: never started.
        self.cortex.catalog.side_effect = lambda data_type=None, name=None: (
            [CatalogEntry("cx-ai", name, ("file",))] if name else [])

    def instantiate(self, name):
        return self.cortex if name == "cortex" else AiModelConnector(CONFIG)

    # What the retired provider path (queue_provider_analysis + finish_provider_analysis) gave for
    # the same mail (one safe Yara body report, so the blend reads the AI) and the same server
    # answer, recorded by running it on a6b58fb5; and with the AI missing (no provider enabled).
    OLD_FIELDS = {"results_ai": "Dangerous", "score_ai": 7.0, "confidence_ai": 82.0,
                  "category_ai": "Classic_phishing", "results": "Suspicious", "score": 7.0,
                  "final_score": 7.0, "confidence": 82.0, "final_confidence": 82.0,
                  "lifecycle_state": "FINALIZED", "inconclusive_reason": "", "verdict_rationale": []}
    OLD_MISSING_FIELDS = {"results_ai": "Inconclusive", "score_ai": 0.0, "confidence_ai": 0.0,
                          "category_ai": "Uncategorized", "results": "Inconclusive", "score": 2.0,
                          "final_score": 2.0, "confidence": 60.0, "final_confidence": 60.0,
                          "lifecycle_state": "FINALIZED", "inconclusive_reason": "", "verdict_rationale": []}
    OLD_ASSESSMENT = {
        "model_version": "v0", "result": "DANGEROUS", "sub_class": "CLASSIC_PHISHING", "score": 7.0,
        "confidence": 82.0, "probabilities": {"SAFE": "5.00%", "UNWANTED": "10.00%", "DANGEROUS": "85.00%"},
        "sub_probabilities": {"CLASSIC_PHISHING": "70.00%"}, "tier": "",
        "contributing_phrases": [["verify", 0.3]], "similar_cases": [], "campaign_embedding": "[0.1, 0.2]",
        "embedding_version": "cmp-e1", "latency_ms": 12}

    def add_body_report(self):
        """A scored Cortex-style vote: a safe Yara report on the mail body."""
        mail = self.case.fileOrMail.mail
        mail.mail_body = MailBody.objects.create(body_value="hi", fuzzy_hash="parity-body")
        mail.save(update_fields=["mail_body"])
        analyzer = Analyzer.objects.create(name="Yara_Parity", analyzer_cortex_id="Yara_Parity", tier=2)
        AnalyzerReport.objects.create(
            cortex_job_id="parity-body", type="mail_body", status="Success", analyzer=analyzer,
            mail_body=mail.mail_body, level="safe", confidence=60, score=2,
            report_summary={}, report_taxonomy={}, report_full={})

    def votes(self, case):
        return sorted((v.analyzer, v.weight, v.band) for v in collect_votes(case, collect_signals(case)[1]))

    def dispatch_ai_intent(self):
        with mock.patch("connectors.tasks.run_engine_job.delay") as delay, \
                self.captureOnCommitCallbacks(execute=True):
            dispatch_case_analysis.run(self.case.id, [("mail_feeder.mailarchive", self.archive.pk, "ai_archive")])
        return delay

    def test_the_recorded_verdicts_depend_on_the_ai(self):
        self.assertNotEqual(self.OLD_FIELDS["results"], self.OLD_MISSING_FIELDS["results"])

    @mock.patch("cortex_job.cortex_utils.reconciliation.emit_connector_event")
    def test_the_ai_vote_and_verdict_equal_the_old_paths(self, _):
        self.add_body_report()
        delay = self.dispatch_ai_intent()
        self.cortex.start.assert_not_called()
        self.assertFalse(AnalyzerReport.objects.filter(analyzer__name=ai_analyzer_name()).exists())
        row = CaseAnalyzerJob.objects.get()
        self.assertEqual(row.analyzer.source, "ai_model")
        delay.assert_called_once_with(row.id)
        self.reconcile.reset_mock()
        self.run_task(row)
        self.reconcile.delay.assert_called_once_with(self.case.id)
        reconcile_case_core(Case.objects.get(pk=self.case.pk))

        new = Case.objects.get(pk=self.case.pk)
        self.assertEqual({f: getattr(new, f) for f in self.OLD_FIELDS}, self.OLD_FIELDS)
        self.assertEqual(self.ai_fields(new), DANGEROUS_FIELDS)
        self.assertEqual(self.votes(new), [(ai_analyzer_name(), 0.2, Result.SUSPICIOUS),
                                           ("Yara_Parity", 0.2, Result.SAFE)])
        fresh = {k: v for k, v in AiAssessment.objects.filter(case=new).values().get().items()
                 if k not in ("id", "case_id", "created_at", "updated_at")}
        self.assertEqual(fresh, self.OLD_ASSESSMENT)

    @mock.patch("cortex_job.cortex_utils.reconciliation.emit_connector_event")
    def test_the_verdict_with_the_ai_missing_equals_the_old_paths(self, _):
        ConnectorState.objects.filter(name="ai_model").update(enabled=False)
        self.add_body_report()
        self.dispatch_ai_intent()
        self.assertFalse(CaseAnalyzerJob.objects.exists())
        reconcile_case_core(Case.objects.get(pk=self.case.pk))

        new = Case.objects.get(pk=self.case.pk)
        self.assertEqual({f: getattr(new, f) for f in self.OLD_MISSING_FIELDS}, self.OLD_MISSING_FIELDS)
        self.assertEqual(self.votes(new), [("Yara_Parity", 0.2, Result.SAFE)])
        self.assertFalse(AiAssessment.objects.exists())
