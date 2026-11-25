"""connectors.engines deferred jobs: a start that defers, and run_engine_job closing the row."""
from types import SimpleNamespace
from unittest import mock

import pybreaker
from celery.exceptions import Retry
from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase

from case_handler.models import Case
from common.http_client import BREAKERS
from connectors import engines
from connectors.base import (
    DATA_TYPE_MAIL_ARCHIVE,
    FETCH_RESULT,
    FETCH_UNKNOWN,
    PROVIDER_KIND_ANALYSIS,
    CatalogEntry,
    Connector,
    ConnectorManifest,
    FetchResult,
    HealthStatus,
    StartResult,
)
from connectors.models import ConnectorDelivery, ConnectorState
from connectors.providers import ProviderUnavailable
from connectors.registry import ConnectorRegistry
from connectors.tasks import run_engine_job
from cortex_job.cortex_utils.cortex_and_job_management import CortexJob
from cortex_job.models import Analyzer, AnalyzerReport, CaseAnalyzerJob

ROLES = {"yara": "Yara", "header": "Header", "ai": "MailAI"}
CONFIGS = {"integrations.cortex": {"analyzers": ROLES}}
ANALYZER_LOG = "tasp.cron.fetch_and_process_emails"  # get_analyzer_db's logger, not propagated
SUCCESS = FetchResult(FETCH_RESULT, "Success", payload={"verdict": "x"})


class Deferred(Connector):
    manifest = ConnectorManifest(name="deferred", version="0.0.1", provides=PROVIDER_KIND_ANALYSIS)
    offered = [
        CatalogEntry("mail_classifier", "MailAI", (DATA_TYPE_MAIL_ARCHIVE,)),
        CatalogEntry("other", "Other", (DATA_TYPE_MAIL_ARCHIVE,)),
    ]
    calls: list = []
    result = SUCCESS
    error = None
    started_error = None
    result_error = None
    on_run = None

    def health_check(self):
        return HealthStatus(ok=True)

    def catalog(self, data_type=None, name=None):
        return [x for x in self.offered if (name and x.name == name) or (data_type and data_type in x.data_types)]

    def start(self, analyzer, data_type, value):
        type(self).calls.append(("start", analyzer.name, data_type, value))
        return StartResult(job_id=f"job{len(type(self).calls)}", deferred=True)

    def run(self, job_id, data_type, value):
        type(self).calls.append(("run", job_id, data_type, value))
        if type(self).on_run:
            type(self).on_run()
        if type(self).error:
            raise type(self).error
        return type(self).result

    def on_started(self, case, analyzer_name):
        type(self).calls.append(("on_started", case.id, analyzer_name))
        if type(self).started_error:
            raise type(self).started_error

    def on_result(self, case, analyzer_name, result):
        type(self).calls.append(("on_result", case.id, analyzer_name, result))
        if type(self).result_error:
            raise type(self).result_error


class UrlOnly(Deferred):
    manifest = ConnectorManifest(name="urlonly", version="0.0.1", provides=PROVIDER_KIND_ANALYSIS)
    offered = [CatalogEntry("mail_classifier", "MailAI", ("url",))]


class SelectMailArchiveTest(SimpleTestCase):
    def test_only_the_ai_role_is_selected(self):
        offered = [CatalogEntry("a", n, (DATA_TYPE_MAIL_ARCHIVE,)) for n in ("Yara", "MailAI", "Other")]
        selected = engines.select_analyzers(DATA_TYPE_MAIL_ARCHIVE, None, offered, ROLES)
        self.assertEqual([x.name for x in selected], ["MailAI"])

    def test_an_ai_named_analyzer_without_mail_archive_is_not_selected(self):
        offered = [CatalogEntry("a", "MailAI", ("url",))]
        self.assertEqual(engines.select_analyzers(DATA_TYPE_MAIL_ARCHIVE, None, offered, ROLES), [])

    def test_get_data_value_is_the_case_id(self):
        self.assertEqual(CortexJob.get_data_value(SimpleNamespace(id=42), DATA_TYPE_MAIL_ARCHIVE), "42")


class DeferredTest(TestCase):
    def setUp(self):
        patcher = mock.patch.dict(BREAKERS)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.registry = ConnectorRegistry()
        self.registry.register(Deferred)
        self.registry.register(UrlOnly)
        for target in ("connectors.engines.registry", "connectors.delivery.registry",
                       "connectors.dispatch.registry", "connectors.registry.registry"):
            patcher = mock.patch(target, self.registry)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch("settings.config.get_section", side_effect=lambda n: CONFIGS.get(n, {}))
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch("tasp.tasks.reconcile_case")
        self.reconcile = patcher.start()
        self.addCleanup(patcher.stop)
        Deferred.calls = []
        for attr in ("error", "started_error", "result_error", "on_run"):
            self.addCleanup(setattr, Deferred, attr, None)
        self.addCleanup(setattr, Deferred, "result", SUCCESS)
        ConnectorState.objects.create(name="deferred", enabled=True)
        user = get_user_model().objects.create_user(username="deferred", password="x")
        self.case = Case.objects.create(status="On Going", description="", reporter=user)

    def calls(self, kind):
        return [c for c in Deferred.calls if c[0] == kind]

    def dispatch(self):
        with mock.patch("connectors.tasks.run_engine_job.delay") as delay, \
                self.captureOnCommitCallbacks(execute=True):
            ids = engines.dispatch(value=self.case, data_type=DATA_TYPE_MAIL_ARCHIVE, case=self.case)
        self.delay = delay
        return ids

    def run_task(self, row, retries=0):
        with self.captureOnCommitCallbacks(execute=True):
            run_engine_job.apply(args=(row.id,), retries=retries)
        row.refresh_from_db()
        return row

    def started_row(self):
        self.dispatch()
        return CaseAnalyzerJob.objects.get()

    # ── dispatch ────────────────────────────────────────────────────────────

    def test_dispatch_writes_one_reportless_pending_row(self):
        ids = self.dispatch()
        self.assertEqual(ids, ["deferred-job1"])
        row = CaseAnalyzerJob.objects.get()
        self.assertEqual((row.cortex_job_id, row.status, row.analyzer_report, row.completed_at),
                         ("deferred-job1", CaseAnalyzerJob.STATUS_INPROGRESS, None, None))
        self.assertEqual((row.analyzer.name, row.analyzer.analyzer_cortex_id, row.analyzer.source),
                         ("MailAI", "deferred:mail_classifier", "deferred"))
        self.assertFalse(AnalyzerReport.objects.exists())
        self.assertEqual(self.calls("start"), [("start", "MailAI", DATA_TYPE_MAIL_ARCHIVE, str(self.case.id))])
        self.assertEqual(self.calls("on_started"), [("on_started", self.case.id, "MailAI")])
        self.delay.assert_called_once_with(row.id)

    def test_on_started_error_keeps_the_row(self):
        Deferred.started_error = RuntimeError("secret text")
        with self.assertLogs("connectors.engines", "ERROR") as logs:
            self.assertEqual(self.dispatch(), ["deferred-job1"])
        self.assertIn("RuntimeError", "\n".join(logs.output))
        self.assertNotIn("secret text", "\n".join(logs.output))
        self.assertEqual(CaseAnalyzerJob.objects.get().status, CaseAnalyzerJob.STATUS_INPROGRESS)
        self.delay.assert_called_once()

    def test_an_engine_not_declaring_mail_archive_is_not_started(self):
        ConnectorState.objects.update(enabled=False)
        ConnectorState.objects.create(name="urlonly", enabled=True)
        self.assertEqual(self.dispatch(), [])
        self.assertEqual(self.calls("start"), [])
        self.assertFalse(CaseAnalyzerJob.objects.exists())

    def test_an_old_provider_row_is_adopted_without_warning(self):
        Analyzer.objects.create(name="MailAI", analyzer_cortex_id="provider:MailAI", source="cortex")
        with self.assertNoLogs(level="WARNING"), self.assertNoLogs(ANALYZER_LOG, "WARNING"):
            self.assertEqual(self.dispatch(), ["deferred-job1"])
        analyzer = Analyzer.objects.get()
        self.assertEqual((analyzer.source, analyzer.analyzer_cortex_id), ("deferred", "provider:MailAI"))
        self.assertEqual(CaseAnalyzerJob.objects.get().analyzer, analyzer)

    def test_an_own_row_with_another_id_is_reused_without_warning(self):
        Analyzer.objects.create(name="MailAI", analyzer_cortex_id="deferred:old", source="deferred")
        with self.assertNoLogs(level="WARNING"), self.assertNoLogs(ANALYZER_LOG, "WARNING"):
            self.assertEqual(self.dispatch(), ["deferred-job1"])
        self.assertEqual(CaseAnalyzerJob.objects.get().analyzer, Analyzer.objects.get())

    def test_a_real_id_row_of_another_source_is_adopted_for_mail_archive(self):
        # The prod shape: a Cortex-owned row with a real Cortex id. A mail_archive entry adopts it
        # (id kept); a non-mail_archive entry with such a clash is still skipped
        # (test_engines_dispatch.test_name_owned_by_another_source_is_skipped).
        Analyzer.objects.create(name="MailAI", analyzer_cortex_id="abc123", source="cortex")
        with self.assertNoLogs("connectors.engines", "ERROR"):
            self.assertEqual(self.dispatch(), ["deferred-job1"])
        analyzer = Analyzer.objects.get()
        self.assertEqual((analyzer.source, analyzer.analyzer_cortex_id), ("deferred", "abc123"))
        row = self.run_task(CaseAnalyzerJob.objects.get())
        self.assertEqual(row.status, CaseAnalyzerJob.STATUS_SUCCESS)
        self.assertEqual(len(self.calls("on_result")), 1)

    def test_adoption_is_idempotent(self):
        Analyzer.objects.create(name="MailAI", analyzer_cortex_id="abc123", source="cortex")
        self.dispatch()
        self.dispatch()
        self.assertEqual(Analyzer.objects.count(), 1)
        self.assertEqual(Analyzer.objects.get().source, "deferred")
        self.assertEqual(set(CaseAnalyzerJob.objects.values_list("analyzer", flat=True)), {Analyzer.objects.get().pk})

    # ── run_engine_job ──────────────────────────────────────────────────────

    def test_success_closes_the_row(self):
        row = self.run_task(self.started_row())
        self.assertEqual(row.status, CaseAnalyzerJob.STATUS_SUCCESS)
        self.assertIsNotNone(row.completed_at)
        self.assertEqual(self.calls("run"), [("run", "job1", DATA_TYPE_MAIL_ARCHIVE, str(self.case.id))])
        self.assertEqual(self.calls("on_result"), [("on_result", self.case.id, "MailAI", SUCCESS)])
        delivery = ConnectorDelivery.objects.get()
        self.assertEqual((delivery.connector, delivery.event, delivery.status, delivery.error,
                          delivery.case_id, delivery.attempt),
                         ("deferred", "analyze", "success", "", self.case.id, 1))
        self.reconcile.delay.assert_called_once_with(self.case.id)

    def test_a_success_delivery_carries_the_payload_reason(self):
        Deferred.result = FetchResult(FETCH_RESULT, "Success", payload={"reason": "a note"})
        self.run_task(self.started_row())
        delivery = ConnectorDelivery.objects.get()
        self.assertEqual((delivery.status, delivery.error), ("success", "a note"))

    def test_failure_result_fails_the_row(self):
        Deferred.result = FetchResult(FETCH_RESULT, "Failure", payload={"reason": "no archive"})
        row = self.run_task(self.started_row())
        self.assertEqual(row.status, CaseAnalyzerJob.STATUS_FAILURE)
        self.assertIsNotNone(row.completed_at)
        self.assertEqual(self.calls("on_result")[0][3], Deferred.result)
        delivery = ConnectorDelivery.objects.get()
        self.assertEqual((delivery.status, delivery.error), ("failed", "no archive"))
        self.reconcile.delay.assert_called_once_with(self.case.id)

    def assert_failed(self, row, text):
        self.assertEqual(row.status, CaseAnalyzerJob.STATUS_FAILURE)
        self.assertIsNotNone(row.completed_at)
        (_, _, _, result), = self.calls("on_result")
        self.assertEqual((result.state, result.status), (FETCH_RESULT, "Failure"))
        self.assertIn(text, result.payload["reason"])
        delivery = ConnectorDelivery.objects.get()
        self.assertEqual((delivery.event, delivery.status), ("analyze", "failed"))
        self.assertIn(text, delivery.error)
        self.reconcile.delay.assert_called_once_with(self.case.id)

    def test_retryable_unavailable_retries_twice_then_fails(self):
        row = self.started_row()
        Deferred.error = ProviderUnavailable("server down")
        with mock.patch.object(run_engine_job, "retry", wraps=run_engine_job.retry) as retry:
            for retries in (0, 1):  # eager mode propagates Retry: redeliver by hand
                with self.assertRaises(Retry):
                    self.run_task(row, retries)
                row.refresh_from_db()
                self.assertEqual(row.status, CaseAnalyzerJob.STATUS_INPROGRESS)
            row = self.run_task(row, retries=2)
        self.assertEqual(len(self.calls("run")), 3)
        first, second = (c.kwargs["countdown"] for c in retry.call_args_list)
        self.assertTrue(5 <= first < 8 and 10 <= second < 13, (first, second))
        self.assert_failed(row, "server down")
        self.assertEqual(ConnectorDelivery.objects.get().attempt, 3)

    def test_non_retryable_unavailable_fails_at_once(self):
        Deferred.error = ProviderUnavailable("model not ready", retryable=False)
        with mock.patch.object(run_engine_job, "retry") as retry:
            row = self.run_task(self.started_row())
        retry.assert_not_called()
        self.assert_failed(row, "model not ready")

    def test_other_error_fails_at_once(self):
        Deferred.error = ValueError("HTTP 400")
        with mock.patch.object(run_engine_job, "retry") as retry:
            row = self.run_task(self.started_row())
        retry.assert_not_called()
        self.assert_failed(row, "HTTP 400")

    def test_a_non_result_state_fails(self):
        Deferred.result = FetchResult(FETCH_UNKNOWN)
        self.assert_failed(self.run_task(self.started_row()), "unknown")

    def test_a_second_run_of_a_closed_row_does_nothing(self):
        row = self.run_task(self.started_row())
        self.run_task(row)
        self.assertEqual(len(self.calls("run")), 1)
        self.assertEqual(len(self.calls("on_result")), 1)
        self.assertEqual(ConnectorDelivery.objects.count(), 1)

    def test_missing_row_does_nothing(self):
        run_engine_job.apply(args=(999999,))
        self.assertEqual(self.calls("run"), [])

    def test_a_row_closed_by_a_racing_run_is_not_claimed_twice(self):
        row = self.started_row()
        Deferred.on_run = lambda: CaseAnalyzerJob.objects.filter(pk=row.pk).update(
            status=CaseAnalyzerJob.STATUS_FAILURE)
        row = self.run_task(row)
        self.assertEqual(row.status, CaseAnalyzerJob.STATUS_FAILURE)
        self.assertIsNone(row.completed_at)
        self.assertEqual(self.calls("on_result"), [])
        self.assertFalse(ConnectorDelivery.objects.exists())
        self.reconcile.delay.assert_not_called()

    def test_a_connector_disabled_after_the_start_still_runs(self):
        row = self.started_row()
        ConnectorState.objects.update(enabled=False)
        row = self.run_task(row)
        self.assertEqual(row.status, CaseAnalyzerJob.STATUS_SUCCESS)
        self.assertEqual(len(self.calls("run")), 1)

    def test_an_open_breaker_fails_without_running(self):
        row = self.started_row()
        breaker = pybreaker.CircuitBreaker(fail_max=1, reset_timeout=60)
        breaker.open()
        BREAKERS["deferred"] = breaker
        row = self.run_task(row)
        self.assertEqual(self.calls("run"), [])
        self.assert_failed(row, "CircuitBreakerError")

    def test_on_result_error_still_closes_the_row_as_failure(self):
        Deferred.result_error = RuntimeError("secret text")
        with self.assertLogs("connectors.tasks", "ERROR") as logs:
            row = self.run_task(self.started_row())
        self.assertIn("RuntimeError", "\n".join(logs.output))
        self.assertEqual(row.status, CaseAnalyzerJob.STATUS_FAILURE)
        self.assertIsNotNone(row.completed_at)
        delivery = ConnectorDelivery.objects.get()
        self.assertEqual(delivery.status, "failed")
        self.assertIn("RuntimeError", delivery.error)
        self.reconcile.delay.assert_called_once_with(self.case.id)

    def test_task_options(self):
        self.assertIs(run_engine_job.acks_late, True)
        self.assertIs(run_engine_job.reject_on_worker_lost, True)
        self.assertEqual(run_engine_job.max_retries, 2)
