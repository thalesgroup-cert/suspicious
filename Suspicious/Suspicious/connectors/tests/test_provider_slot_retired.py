"""The mail_ai provider slot is retired: its names are gone, the one-release forwarder finishes rows
the old code queued before the upgrade, and the engine layer stays AI-free."""
import inspect
from unittest import mock
from uuid import uuid4

from celery.exceptions import Retry
from django.test import SimpleTestCase, TestCase

from ai_model.mailinfo import mark_ai_missing
from ai_model.models import AiAssessment
from connectors import base, engines, providers, tasks
from connectors.base import ConnectorManifest
from connectors.contrib.ai_model.connector import AiModelConnector
from connectors.contrib.ai_model.tests.test_connector import CONFIG, make_mail_case
from connectors.contrib.ai_model.tests.test_engine_path import DANGEROUS_FIELDS, EnginePathMixin
from connectors.contrib.cortex.connector import CortexConnector
from connectors.models import ConnectorDelivery
from connectors.providers import ProviderUnavailable
from connectors.registry import ConnectorRegistry
from connectors.tasks import run_provider_analysis
from connectors.tests.dummy import DummyConnector
from cortex_job.cortex_utils.cortex_and_job_management import ai_analyzer_name
from cortex_job.models import Analyzer, CaseAnalyzerJob

REMOVED = {
    base: ("PROVIDER_KIND_MAIL_AI", "ProviderResult"),
    providers: ("queue_provider_analysis", "queue_mail_ai", "finish_provider_analysis",
                "enabled_provider", "provider_connector", "PROVIDER_JOB_PREFIX"),
}
AI_WORDS = ("ai_model", "AiAssessment", "results_ai")


class RemovedNamesTest(SimpleTestCase):
    def test_the_provider_slot_names_are_gone(self):
        for module, names in REMOVED.items():
            for name in names:
                with self.subTest(module=module.__name__, name=name):
                    self.assertFalse(hasattr(module, name))
        self.assertFalse(hasattr(base.Connector, "analyze"))

    def test_provider_unavailable_is_still_importable(self):
        self.assertTrue(issubclass(ProviderUnavailable, Exception))
        self.assertFalse(ProviderUnavailable("x", retryable=False).retryable)

    def test_mail_ai_is_no_longer_a_valid_provides(self):
        self.assertEqual(base.VALID_PROVIDER_KINDS, frozenset({base.PROVIDER_KIND_ANALYSIS}))
        with self.assertRaises(ValueError):
            ConnectorManifest(name="x1", version="1", provides="mail_ai").validate()
        ConnectorManifest(name="x1", version="1", provides="analysis").validate()
        ConnectorManifest(name="x1", version="1").validate()

    def test_registry_providers_lists_only_the_matching_kind(self):
        registry = ConnectorRegistry()
        for cls in (DummyConnector, AiModelConnector):
            registry.register(cls)
        self.assertEqual(registry.providers("analysis"), ["ai_model"])
        self.assertEqual(registry.providers("mail_ai"), [])

    def test_the_forwarder_keeps_the_old_task_options(self):
        self.assertEqual(run_provider_analysis.name, "connectors.tasks.run_provider_analysis")
        self.assertIs(run_provider_analysis.acks_late, True)
        self.assertIs(run_provider_analysis.reject_on_worker_lost, True)
        self.assertEqual(run_provider_analysis.max_retries, 2)


class EngineLayerIsAiFreeTest(SimpleTestCase):
    """Scoped to the engine code paths: the same files hold older, legitimate mentions (the
    campaign tasks in connectors/tasks.py, the forwarder's fallback)."""

    def test_no_engine_code_path_names_the_ai(self):
        functions = [tasks.run_engine_job.run, tasks._run_deferred_job, tasks._close_engine_job]
        functions += [getattr(engines, name) for name in (
            "dispatch", "_dispatch", "_dispatch_engine", "_analyzer_row", "_start", "_start_deferred",
            "store_result", "apply_result", "update_report", "refresh", "close_row", "handle_webhook",
        )]
        for function in functions + [base.Connector]:
            source = inspect.getsource(function)
            for word in AI_WORDS:
                with self.subTest(function=function.__name__, word=word):
                    self.assertNotIn(word, source)


class ForwarderTest(EnginePathMixin, TestCase):
    """run_provider_analysis(case_id, kind, job_id) as an old worker queued it."""

    def old_row(self, case=None, source="ai_model", analyzer_id=None):
        """What queue_provider_analysis wrote: a report-less pending row with a provider- id."""
        case = case or self.case
        name = ai_analyzer_name()
        analyzer, _ = Analyzer.objects.get_or_create(
            name=name, defaults={"analyzer_cortex_id": analyzer_id or "provider:" + name, "source": source})
        mark_ai_missing(case)
        return CaseAnalyzerJob.objects.create(
            case=case, cortex_job_id="provider-" + uuid4().hex[:30], analyzer=analyzer,
            status=CaseAnalyzerJob.STATUS_INPROGRESS)

    def forward(self, job_id, retries=0):
        with self.captureOnCommitCallbacks(execute=True):
            run_provider_analysis.apply(args=(self.case.id, "mail_ai", job_id), retries=retries)
        self.case.refresh_from_db()

    def assessment(self, case):
        return {k: v for k, v in AiAssessment.objects.filter(case=case).values().get().items()
                if k not in ("id", "case_id", "created_at", "updated_at")}

    def test_an_old_row_finishes_like_an_engine_row(self):
        row = self.old_row()
        self.forward(row.id)
        row.refresh_from_db()
        self.assertEqual(row.status, CaseAnalyzerJob.STATUS_SUCCESS)
        self.assertEqual(self.ai_fields(), DANGEROUS_FIELDS)
        delivery = ConnectorDelivery.objects.get()
        self.assertEqual((delivery.connector, delivery.event, delivery.status), ("ai_model", "analyze", "success"))
        self.reconcile.delay.assert_called_once_with(self.case.id)

        engine_case, _ = make_mail_case(n=2)
        engine_row = CaseAnalyzerJob.objects.get(cortex_job_id=self.dispatch(engine_case)[0])
        with self.captureOnCommitCallbacks(execute=True):
            tasks.run_engine_job.apply(args=(engine_row.id,))
        self.assertEqual(self.ai_fields(engine_case), self.ai_fields())
        self.assertEqual(self.assessment(engine_case), self.assessment(self.case))

    def test_a_closed_row_does_nothing(self):
        row = self.old_row()
        CaseAnalyzerJob.objects.filter(pk=row.pk).update(status=CaseAnalyzerJob.STATUS_FAILURE)
        self.forward(row.id)
        self.classify.assert_not_called()
        self.assertFalse(ConnectorDelivery.objects.exists())
        self.reconcile.delay.assert_not_called()

    def test_a_missing_row_does_nothing(self):
        self.forward(987654)
        self.classify.assert_not_called()
        self.assertFalse(ConnectorDelivery.objects.exists())
        self.reconcile.delay.assert_not_called()

    def test_a_retryable_error_retries_the_forwarder(self):
        self.classify.side_effect = ProviderUnavailable("down")
        row = self.old_row()
        with self.assertRaises(Retry):
            self.forward(row.id)
        row.refresh_from_db()
        self.assertEqual(row.status, CaseAnalyzerJob.STATUS_INPROGRESS)

    def test_an_unregistered_source_falls_back_to_ai_model(self):
        row = self.old_row(source="gone_engine")
        self.forward(row.id)
        row.refresh_from_db()
        self.assertEqual(row.status, CaseAnalyzerJob.STATUS_SUCCESS)
        self.assertEqual(self.ai_fields(), DANGEROUS_FIELDS)
        self.assertEqual(ConnectorDelivery.objects.get().connector, "ai_model")


class ForwarderCortexRowTest(EnginePathMixin, TestCase):
    """The prod shape: the AI row belongs to Cortex with a real Cortex id (old get_or_create took
    whatever row had the name). The forwarder runs ai_model, never Cortex."""

    engines = (AiModelConnector, CortexConnector)

    def setUp(self):
        super().setUp()
        self.cortex = mock.Mock()
        self.cortex.catalog.return_value = []  # enabled by default; offers nothing for the mail

    def instantiate(self, name):
        return self.cortex if name == "cortex" else AiModelConnector(CONFIG)

    def test_a_cortex_owned_row_is_run_by_ai_model(self):
        from common.http_client import get_breaker

        row = ForwarderTest.old_row(self, source="cortex", analyzer_id="5f3a9c1d2e")
        with mock.patch("common.http_client.get_breaker", wraps=get_breaker) as breaker:
            ForwarderTest.forward(self, row.id)
        self.cortex.run.assert_not_called()
        self.assertNotIn(mock.call("cortex"), breaker.call_args_list)
        row.refresh_from_db()
        self.assertEqual(row.status, CaseAnalyzerJob.STATUS_SUCCESS)
        self.assertEqual(ConnectorDelivery.objects.get().connector, "ai_model")

        engine_case, _ = make_mail_case(n=2)
        engine_row = CaseAnalyzerJob.objects.get(cortex_job_id=self.dispatch(engine_case)[0])
        with self.captureOnCommitCallbacks(execute=True):
            tasks.run_engine_job.apply(args=(engine_row.id,))
        self.assertEqual(self.ai_fields(), DANGEROUS_FIELDS)
        self.assertEqual(self.ai_fields(engine_case), self.ai_fields())
        self.assertEqual(ForwarderTest.assessment(self, engine_case), ForwarderTest.assessment(self, self.case))


class ForwarderWithoutAiModelTest(EnginePathMixin, TestCase):
    engines = (CortexConnector,)  # the row's source is registered, ai_model is not

    def setUp(self):
        super().setUp()
        self.cortex = mock.Mock()

    def instantiate(self, name):
        return self.cortex

    def test_the_row_is_closed_failure_and_cortex_never_runs_it(self):
        row = ForwarderTest.old_row(self, source="cortex", analyzer_id="5f3a9c1d2e")
        ForwarderTest.forward(self, row.id)
        row.refresh_from_db()
        self.assertEqual(row.status, CaseAnalyzerJob.STATUS_FAILURE)
        self.cortex.run.assert_not_called()
        delivery = ConnectorDelivery.objects.get()
        self.assertEqual((delivery.connector, delivery.status, delivery.error),
                         ("ai_model", "failed", "no engine for this job"))
        self.reconcile.delay.assert_called_once_with(self.case.id)


class ForwarderWithoutEngineTest(EnginePathMixin, TestCase):
    engines = ()  # neither the row's source nor ai_model is registered

    def test_the_row_is_closed_failure_with_a_failed_delivery(self):
        row = ForwarderTest.old_row(self, source="gone_engine")
        ForwarderTest.forward(self, row.id)
        row.refresh_from_db()
        self.assertEqual(row.status, CaseAnalyzerJob.STATUS_FAILURE)
        self.assertIsNotNone(row.completed_at)
        self.classify.assert_not_called()
        self.assertEqual(self.case.results_ai, "Inconclusive")
        delivery = ConnectorDelivery.objects.get()
        self.assertEqual((delivery.connector, delivery.event, delivery.status, delivery.error),
                         ("ai_model", "analyze", "failed", "no engine for this job"))
        self.reconcile.delay.assert_called_once_with(self.case.id)
