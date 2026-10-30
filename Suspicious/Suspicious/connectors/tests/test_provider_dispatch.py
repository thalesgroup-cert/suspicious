"""mail_ai provider slot: queue the case, run the provider, close the ledger row."""
from datetime import timedelta
from unittest import mock

import pybreaker
from celery.exceptions import Retry
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from ai_model.models import AiAssessment
from case_handler.lifecycle import LifecycleState
from case_handler.models import Case, CaseHasFileOrMail
from common.http_client import BREAKERS
from connectors.base import ProviderResult
from connectors.models import ConnectorDelivery, ConnectorState
from connectors.providers import (
    ProviderUnavailable,
    finish_provider_analysis,
    has_provider_job,
    queue_provider_analysis,
)
from connectors.registry import ConnectorRegistry
from connectors.tasks import run_provider_analysis
from connectors.tests.dummy import DummyProviderConnector
from cortex_job.cortex_utils.cortex_and_job_management import (
    CortexJob,
    CortexJobManager,
    _get_cortex_config,
)
from cortex_job.cortex_utils.reconciliation import reconcile_case_core
from cortex_job.models import Analyzer, AnalyzerReport, CaseAnalyzerJob
from file_process.models import File
from hash_process.models import Hash
from mail_feeder.models import Mail, MailArchive, MailInfo

DANGEROUS = ProviderResult(
    "DANGEROUS", 7, 81, "Classic_phishing", "v0", {"sub_class": "CLASSIC_PHISHING"}
)


def ai_name():
    return _get_cortex_config()["analyzers"]["ai"]


def make_mail_case(n=1):
    user = get_user_model().objects.create_user(username=f"prov{n}", password="x")
    mail = Mail.objects.create(
        subject="s", reportedBy="r", date=timezone.now(), to="t", mail_id=f"m{n}"
    )
    case = Case.objects.create(description="", reporter=user, dispatched_at=timezone.now())
    case.fileOrMail = CaseHasFileOrMail.objects.create(case=case, mail=mail)
    case.save(update_fields=["fileOrMail"])
    MailInfo.objects.create(user=user, mail=mail)
    archive = File.objects.create(
        linked_hash=Hash.objects.create(value=f"hash{n}"), tmp_path=f"mail{n}.tar.gz"
    )
    return case, MailArchive.objects.create(mail=mail, archive=archive)


class ProviderDispatchTest(TestCase):
    def setUp(self):
        breakers = mock.patch.dict(
            BREAKERS, {"dummy_provider": pybreaker.CircuitBreaker(fail_max=5, reset_timeout=60)}
        )
        breakers.start()
        self.addCleanup(breakers.stop)
        registry = ConnectorRegistry()
        registry.register(DummyProviderConnector)
        for target in ("connectors.providers.registry", "connectors.delivery.registry"):
            patcher = mock.patch(target, registry)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch("tasp.tasks.reconcile_case")
        self.reconcile = patcher.start()
        self.addCleanup(patcher.stop)
        DummyProviderConnector.result, DummyProviderConnector.error = DANGEROUS, None
        self.addCleanup(setattr, DummyProviderConnector, "result", None)
        self.addCleanup(setattr, DummyProviderConnector, "error", None)
        ConnectorState.objects.create(name="dummy_provider", enabled=True)
        self.case, self.archive = make_mail_case()

    def queue(self):
        return queue_provider_analysis(self.case, "mail_ai")

    def run_task(self, job, retries=0):
        with self.captureOnCommitCallbacks(execute=True):
            run_provider_analysis.apply(args=(self.case.id, "mail_ai", job.id), retries=retries)
        job.refresh_from_db()
        self.case.refresh_from_db()
        return job

    def assert_failed(self, job, text):
        self.assertEqual(job.status, CaseAnalyzerJob.STATUS_FAILURE)
        self.assertIsNotNone(job.completed_at)
        self.assertEqual(self.case.results_ai, "Inconclusive")
        delivery = ConnectorDelivery.objects.get()
        self.assertEqual((delivery.event, delivery.status), ("analyze", "failed"))
        self.assertIn(text, delivery.error)
        self.reconcile.delay.assert_called_once_with(self.case.id)

    # ── queue ──────────────────────────────────────────────────────────────

    def test_queue_creates_a_pending_row_for_the_ai_analyzer(self):
        with mock.patch("connectors.tasks.run_provider_analysis") as task, \
                self.captureOnCommitCallbacks(execute=True):
            job = self.queue()
        self.assertEqual((job.status, job.analyzer.name), ("InProgress", ai_name()))
        self.assertTrue(job.cortex_job_id.startswith("provider-"))
        self.assertIsNone(job.analyzer_report)
        task.delay.assert_called_once_with(self.case.id, "mail_ai", job.id)

    def test_queue_reuses_the_configured_ai_analyzer_and_its_weight(self):
        existing = Analyzer.objects.create(name=ai_name(), analyzer_cortex_id="cx-ai", weight=0.7)
        job = self.queue()
        self.assertEqual(job.analyzer, existing)
        existing.refresh_from_db()
        self.assertEqual(existing.weight, 0.7)

    def test_queue_returns_none_without_an_enabled_provider(self):
        ConnectorState.objects.filter(name="dummy_provider").update(enabled=False)
        self.assertIsNone(self.queue())
        self.assertFalse(CaseAnalyzerJob.objects.exists())

    def test_launch_cortex_ai_jobs_hands_over_and_calls_no_cortex_api(self):
        cortex = CortexJob(api_url="http://cortex.invalid", api_key="k")
        cortex.api = mock.Mock()
        with mock.patch.object(CortexJob, "run") as run:
            self.assertIsNone(cortex.launch_cortex_ai_jobs(self.archive, "file", case=self.case))
        run.assert_not_called()
        cortex.api.analyzers.get_by_name.assert_not_called()
        self.assertTrue(has_provider_job(self.case))

    def test_launch_cortex_ai_jobs_still_uses_cortex_without_a_provider(self):
        ConnectorState.objects.filter(name="dummy_provider").update(enabled=False)
        cortex = CortexJob(api_url="http://cortex.invalid", api_key="k")
        cortex.api = mock.Mock()
        with mock.patch.object(CortexJob, "run", return_value=mock.Mock(id="cx-1")) as run:
            self.assertEqual(
                cortex.launch_cortex_ai_jobs(self.archive, "file", case=self.case), "cx-1"
            )
        run.assert_called_once()
        self.assertFalse(has_provider_job(self.case))

    # ── task ───────────────────────────────────────────────────────────────

    def test_task_writes_case_fields_assessment_and_closes_the_row(self):
        job = self.run_task(self.queue())
        self.assertEqual(
            (self.case.results_ai, self.case.score_ai, self.case.confidence_ai,
             self.case.category_ai),
            ("Dangerous", 7, 81, "Classic_phishing"),
        )
        assessment = AiAssessment.objects.get(case=self.case)
        self.assertEqual(
            (assessment.model_version, assessment.result, assessment.sub_class),
            ("v0", "DANGEROUS", "CLASSIC_PHISHING"),
        )
        self.assertEqual(job.status, CaseAnalyzerJob.STATUS_SUCCESS)
        self.assertIsNotNone(job.completed_at)
        info = MailInfo.objects.get(mail=self.archive.mail)
        self.assertEqual((info.is_analyzed, info.is_phishing, info.is_dangerous), (True, True, True))
        delivery = ConnectorDelivery.objects.get()
        self.assertEqual(
            (delivery.connector, delivery.event, delivery.status, delivery.case_id),
            ("dummy_provider", "analyze", "success", self.case.id),
        )
        self.reconcile.delay.assert_called_once_with(self.case.id)

    def test_inconclusive_result_is_a_success_without_mail_flags(self):
        DummyProviderConnector.result = ProviderResult(
            "INCONCLUSIVE", 0, 0, "No subclass found", "v0", {}, reason="empty body"
        )
        job = self.run_task(self.queue())
        self.assertEqual(job.status, CaseAnalyzerJob.STATUS_SUCCESS)
        self.assertEqual(self.case.results_ai, "Inconclusive")
        self.assertEqual(AiAssessment.objects.get(case=self.case).result, "INCONCLUSIVE")
        self.assertFalse(MailInfo.objects.get(mail=self.archive.mail).is_analyzed)
        self.assertEqual(ConnectorDelivery.objects.get().error, "empty body")

    def test_unavailable_after_retries_marks_inconclusive_and_the_row_failed(self):
        job = self.queue()
        with mock.patch.object(
            DummyProviderConnector, "analyze", side_effect=ProviderUnavailable("server down")
        ) as analyze, mock.patch.object(
            run_provider_analysis, "retry", wraps=run_provider_analysis.retry
        ) as retry:
            for retries in (0, 1):  # eager mode propagates Retry: redeliver by hand
                with self.assertRaises(Retry):
                    self.run_task(job, retries)
                job.refresh_from_db()
                self.assertEqual(job.status, CaseAnalyzerJob.STATUS_INPROGRESS)
            job = self.run_task(job, retries=2)
        self.assertEqual(analyze.call_count, 3)
        first, second = (c.kwargs["countdown"] for c in retry.call_args_list)
        self.assertTrue(5 <= first <= 8 and 10 <= second <= 13, (first, second))
        self.assert_failed(job, "server down")
        self.assertEqual(ConnectorDelivery.objects.get().attempt, 3)

    def test_not_retryable_unavailable_fails_without_retrying(self):
        DummyProviderConnector.error = ProviderUnavailable("model not ready", retryable=False)
        with mock.patch.object(run_provider_analysis, "retry") as retry:
            job = self.run_task(self.queue())
        retry.assert_not_called()
        self.assert_failed(job, "model not ready")

    def test_other_errors_fail_without_retrying(self):
        DummyProviderConnector.error = ValueError("HTTP 400")
        with mock.patch.object(run_provider_analysis, "retry") as retry:
            job = self.run_task(self.queue())
        retry.assert_not_called()
        self.assert_failed(job, "HTTP 400")

    def test_a_result_that_cannot_be_stored_closes_the_row_as_failure(self):
        DummyProviderConnector.result = ProviderResult("SAFE", 0, 90, "Ham", "v0", {"nope": 1})
        job = self.run_task(self.queue())
        self.assert_failed(job, "nope")
        self.assertFalse(AiAssessment.objects.exists())

    def test_redelivery_of_a_closed_job_is_a_no_op(self):
        job = self.queue()
        with mock.patch.object(
            DummyProviderConnector, "analyze", return_value=DANGEROUS
        ) as analyze:
            self.run_task(job)
            self.run_task(job)
        self.assertEqual(analyze.call_count, 1)
        self.assertEqual(ConnectorDelivery.objects.count(), 1)
        self.assertFalse(finish_provider_analysis(job.id, DANGEROUS))
        self.reconcile.delay.assert_called_once_with(self.case.id)

    def test_open_breaker_fails_fast(self):
        BREAKERS["dummy_provider"].open()
        with mock.patch.object(DummyProviderConnector, "analyze") as analyze:
            job = self.run_task(self.queue())
        analyze.assert_not_called()
        self.assert_failed(job, "CircuitBreakerError")

    def test_disabled_provider_closes_the_row_as_failure(self):
        job = self.queue()
        ConnectorState.objects.filter(name="dummy_provider").update(enabled=False)
        with mock.patch.object(DummyProviderConnector, "analyze") as analyze:
            job = self.run_task(job)
        analyze.assert_not_called()
        self.assert_failed(job, "mail_ai")

    # ── legacy AI path and reconcile ───────────────────────────────────────

    def test_manage_ai_jobs_skips_cases_with_a_provider_job_but_still_handles_legacy_cases(self):
        # A legacy Cortex AI report on the same (deduplicated) archive file.
        AnalyzerReport.objects.create(
            cortex_job_id="cx-ai-old", type="file", status="Success",
            analyzer=Analyzer.objects.create(name=ai_name(), analyzer_cortex_id="cx-ai"),
            file=self.archive.archive, level="safe", confidence=90, score=0,
            report_summary={}, report_full={"sub_classification": "ham"}, report_taxonomy={},
        )
        self.run_task(self.queue())
        CortexJobManager().manage_ai_jobs(self.case)
        self.case.refresh_from_db()
        self.assertEqual(self.case.results_ai, "Dangerous")

        legacy = Case.objects.create(description="", reporter=self.case.reporter)
        legacy.fileOrMail = CaseHasFileOrMail.objects.create(case=legacy, mail=self.archive.mail)
        legacy.save(update_fields=["fileOrMail"])
        CortexJobManager().manage_ai_jobs(legacy)
        legacy.refresh_from_db()
        self.assertEqual(legacy.results_ai, "Safe")

    @mock.patch("cortex_job.cortex_utils.reconciliation.run_campaign_detection")
    @mock.patch("cortex_job.cortex_utils.reconciliation.emit_connector_event")
    @mock.patch("cortex_job.cortex_utils.reconciliation.finalise")
    def test_reconcile_waits_for_the_provider_row_then_finalises(self, finalise, *_):
        job = self.queue()
        reconcile_case_core(self.case)
        self.case.refresh_from_db()
        self.assertEqual(self.case.lifecycle_state, LifecycleState.ANALYZING)
        finalise.assert_not_called()

        with self.captureOnCommitCallbacks(execute=True):
            self.assertTrue(finish_provider_analysis(job.id, DANGEROUS, connector="dummy_provider"))
        reconcile_case_core(self.case)
        self.case.refresh_from_db()
        self.assertEqual(self.case.lifecycle_state, LifecycleState.FINALIZED)
        finalise.assert_called_once()

    @mock.patch("cortex_job.cortex_utils.reconciliation.run_campaign_detection")
    @mock.patch("cortex_job.cortex_utils.reconciliation.emit_connector_event")
    def test_a_provider_finishing_mid_reconcile_keeps_its_fields(self, *_):
        job = self.queue()
        stale = Case.objects.get(pk=self.case.pk)  # reconcile_case loads it before the ledger sync
        with mock.patch.object(
            CortexJobManager, "update_single_job",
            side_effect=lambda caj: finish_provider_analysis(job.id, DANGEROUS, connector="dummy_provider"),
        ):
            reconcile_case_core(stale)  # finalise is NOT mocked: it scores and saves the case
        self.case.refresh_from_db()
        self.assertEqual(self.case.lifecycle_state, LifecycleState.FINALIZED)
        self.assertEqual(
            (self.case.results_ai, self.case.score_ai, self.case.confidence_ai,
             self.case.category_ai),
            ("Dangerous", 7, 81, "Classic_phishing"),
        )

    def test_a_provider_row_failed_by_fail_stale_jobs_leaves_the_ai_inconclusive(self):
        from tasp.tasks import fail_stale_jobs

        job = self.queue()
        CaseAnalyzerJob.objects.filter(pk=job.pk).update(
            created_at=timezone.now() - timedelta(days=2)
        )
        fail_stale_jobs.apply().get()
        job.refresh_from_db()
        self.case.refresh_from_db()
        self.assertEqual(job.status, CaseAnalyzerJob.STATUS_FAILURE)
        self.assertEqual(self.case.results_ai, "Inconclusive")

    def test_a_failed_enqueue_leaves_the_ai_inconclusive(self):
        with mock.patch.object(
            run_provider_analysis, "apply_async", side_effect=RuntimeError("broker down")
        ), self.assertRaises(RuntimeError), self.captureOnCommitCallbacks(execute=True):
            self.queue()
        self.case.refresh_from_db()
        self.assertTrue(has_provider_job(self.case))
        self.assertEqual(self.case.results_ai, "Inconclusive")
