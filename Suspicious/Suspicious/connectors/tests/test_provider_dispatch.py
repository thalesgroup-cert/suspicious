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
    PROVIDER_JOB_PREFIX,
    ProviderUnavailable,
    finish_provider_analysis,
    queue_provider_analysis,
)
from connectors.registry import ConnectorRegistry
from connectors.tasks import run_provider_analysis
from connectors.tests.dummy import DummyProviderConnector
from cortex_job.cortex_utils.cortex_and_job_management import CortexJobManager, ai_analyzer_name
from cortex_job.cortex_utils.reconciliation import reconcile_case_core
from cortex_job.models import Analyzer, AnalyzerReport, CaseAnalyzerJob
from file_process.models import File
from hash_process.models import Hash
from mail_feeder.models import Mail, MailArchive, MailInfo
from score_process.scoring.collect import collect_signals, collect_votes
from tasp.tasks import dispatch_case_analysis

DANGEROUS = ProviderResult(
    "DANGEROUS", 7, 81, "Classic_phishing", "v0", {"sub_class": "CLASSIC_PHISHING"}
)
SAFE = ProviderResult("SAFE", 1, 95, "Ham", "v0", {"sub_class": "HAM"})
# What the ai_model connector returns when the model gave no answer (model_version "").
NO_ANSWER = ProviderResult(
    "INCONCLUSIVE", 0, 0, "No subclass found", "", {}, reason="archive_unreadable"
)


def ai_name():
    return ai_analyzer_name()


def has_provider_job(case):
    return CaseAnalyzerJob.objects.filter(
        case=case, cortex_job_id__startswith=PROVIDER_JOB_PREFIX
    ).exists()


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

    def test_the_provider_path_and_the_vote_work_without_analyzers_ai(self):
        with mock.patch(
            "cortex_job.cortex_utils.cortex_and_job_management._get_cortex_config",
            return_value={"analyzers": {"yara": "Yara_2_0"}},
        ):
            job = self.run_task(self.queue())
            ai = collect_signals(self.case)[1]
            votes = {v.analyzer: v for v in collect_votes(self.case, ai)}
        self.assertEqual(job.analyzer.name, "AI_Mail_Analyzer")
        self.assertEqual(job.status, CaseAnalyzerJob.STATUS_SUCCESS)
        self.assertEqual(self.case.results_ai, "Dangerous")
        self.assertEqual(votes["AI_Mail_Analyzer"].weight, 0.2)  # the row's default weight

    def test_queue_returns_none_without_an_enabled_provider(self):
        ConnectorState.objects.filter(name="dummy_provider").update(enabled=False)
        self.assertIsNone(self.queue())
        self.assertFalse(CaseAnalyzerJob.objects.exists())

    def dispatch_ai_archive(self):
        # The real CortexJob, against a Cortex API that offers the AI analyzer for every type and
        # accepts every job: an archive routed to Cortex would call it and write Cortex rows.
        with mock.patch(
            "cortex_job.cortex_utils.cortex_and_job_management.SessionCortexApi"
        ) as api_cls:
            api = api_cls.return_value
            analyzer = mock.Mock()
            analyzer.name = ai_name()
            api.analyzers.get_by_type.return_value = [analyzer]
            api.analyzers.get_by_name.return_value = analyzer
            api.analyzers.run_by_name.return_value = mock.Mock(id="cortex-job-1")
            dispatch_case_analysis.run(
                self.case.id, [("mail_feeder.mailarchive", self.archive.pk, "ai_archive")]
            )
        self.assertEqual(api.method_calls, [])
        self.assertFalse(AnalyzerReport.objects.exists())
        self.assertFalse(
            CaseAnalyzerJob.objects.exclude(cortex_job_id__startswith=PROVIDER_JOB_PREFIX).exists()
        )

    def test_an_ai_archive_dispatch_hands_over_and_calls_no_cortex_api(self):
        self.dispatch_ai_archive()
        self.assertTrue(has_provider_job(self.case))
        self.run_task(CaseAnalyzerJob.objects.get())
        self.assertEqual(self.case.results_ai, "Dangerous")

    def test_an_ai_archive_dispatch_without_a_provider_queues_nothing(self):
        ConnectorState.objects.filter(name="dummy_provider").update(enabled=False)
        self.dispatch_ai_archive()
        self.assertFalse(CaseAnalyzerJob.objects.exists())
        # As when the Cortex AI job failed: the AI vote is missing, not the "Suspicious" default.
        self.case.refresh_from_db()
        self.assertEqual(self.case.results_ai, "Inconclusive")
        self.assertIs(collect_signals(self.case)[3], True)

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

    def test_an_empty_model_version_closes_the_row_as_failure_and_stores_no_assessment(self):
        DummyProviderConnector.result = NO_ANSWER
        job = self.run_task(self.queue())
        self.assert_failed(job, "no model_version (archive_unreadable)")
        defaults = {name: Case._meta.get_field(name).get_default()
                    for name in ("score_ai", "confidence_ai", "category_ai")}
        self.assertEqual(defaults["category_ai"], "Uncategorized")  # what the dashboard counts
        self.assertEqual(
            {name: getattr(self.case, name) for name in defaults}, defaults
        )
        self.assertFalse(AiAssessment.objects.exists())
        self.assertFalse(MailInfo.objects.get(mail=self.archive.mail).is_analyzed)

    def test_a_model_inconclusive_result_is_written_like_any_class(self):
        DummyProviderConnector.result = ProviderResult(
            "INCONCLUSIVE", 3, 45, "Clone", "v0", {"sub_class": "CLONE"}
        )
        job = self.run_task(self.queue())
        self.assertEqual(job.status, CaseAnalyzerJob.STATUS_SUCCESS)
        self.assertEqual(
            (self.case.results_ai, self.case.score_ai, self.case.confidence_ai,
             self.case.category_ai),
            ("Inconclusive", 3, 45, "Clone"),
        )
        info = MailInfo.objects.get(mail=self.archive.mail)
        self.assertEqual((info.is_analyzed, info.is_phishing, info.is_dangerous), (True, True, False))

    # ── a second provider row for one case ─────────────────────────────────

    def ai_fields(self):
        self.case.refresh_from_db()
        return (self.case.results_ai, self.case.score_ai, self.case.confidence_ai, self.case.category_ai)

    def test_a_second_successful_row_replaces_the_earlier_rows_case_fields(self):
        self.run_task(self.queue())
        DummyProviderConnector.result = SAFE
        self.run_task(self.queue())
        self.assertEqual(self.ai_fields(), ("Safe", 1, 95, "Ham"))
        self.assertEqual(AiAssessment.objects.get(case=self.case).result, "SAFE")

    def test_the_case_fields_follow_the_latest_finished_row_not_the_latest_queued(self):
        first, second = self.queue(), self.queue()
        DummyProviderConnector.result = SAFE
        self.run_task(second)
        DummyProviderConnector.result = DANGEROUS
        self.run_task(first)
        self.assertEqual(self.ai_fields(), ("Dangerous", 7, 81, "Classic_phishing"))
        self.assertEqual(AiAssessment.objects.get(case=self.case).result, "DANGEROUS")

    def test_a_pending_second_row_keeps_the_earlier_rows_case_fields(self):
        self.run_task(self.queue())
        self.queue()
        self.assertEqual(self.ai_fields(), ("Dangerous", 7, 81, "Classic_phishing"))

    def assert_earlier_success_kept(self, job):
        self.assertEqual(job.status, CaseAnalyzerJob.STATUS_FAILURE)
        self.assertEqual(self.ai_fields(), ("Dangerous", 7, 81, "Classic_phishing"))
        assessment = AiAssessment.objects.get(case=self.case)
        self.assertEqual((assessment.model_version, assessment.result, assessment.sub_class),
                         ("v0", "DANGEROUS", "CLASSIC_PHISHING"))

    def test_a_failed_second_row_keeps_the_earlier_rows_assessment_and_case_fields(self):
        self.run_task(self.queue())
        DummyProviderConnector.error = ValueError("HTTP 400")
        self.assert_earlier_success_kept(self.run_task(self.queue()))

    def test_an_empty_model_version_second_row_keeps_the_earlier_rows_assessment_and_case_fields(self):
        self.run_task(self.queue())
        DummyProviderConnector.result = NO_ANSWER
        self.assert_earlier_success_kept(self.run_task(self.queue()))

    def test_a_stale_failed_second_row_keeps_the_earlier_rows_case_fields(self):
        from tasp.tasks import fail_stale_jobs

        self.run_task(self.queue())
        job = self.queue()
        CaseAnalyzerJob.objects.filter(pk=job.pk).update(created_at=timezone.now() - timedelta(days=2))
        fail_stale_jobs.apply().get()
        job.refresh_from_db()
        self.assert_earlier_success_kept(job)

    def test_the_task_is_acked_late_and_redelivered_on_worker_loss(self):
        self.assertIs(run_provider_analysis.acks_late, True)
        self.assertIs(run_provider_analysis.reject_on_worker_lost, True)
        self.assertEqual(run_provider_analysis.max_retries, 2)

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

    # ── reconcile ──────────────────────────────────────────────────────────

    @mock.patch("cortex_job.cortex_utils.reconciliation.emit_connector_event")
    @mock.patch("cortex_job.cortex_utils.reconciliation.finalise")
    def test_reconcile_waits_for_the_provider_row_then_finalises(self, finalise, *_, result=DANGEROUS):
        job = self.queue()
        reconcile_case_core(self.case)
        self.case.refresh_from_db()
        self.assertEqual(self.case.lifecycle_state, LifecycleState.ANALYZING)
        finalise.assert_not_called()

        with self.captureOnCommitCallbacks(execute=True):
            self.assertTrue(finish_provider_analysis(job.id, result, connector="dummy_provider"))
        reconcile_case_core(self.case)
        self.case.refresh_from_db()
        self.assertEqual(self.case.lifecycle_state, LifecycleState.FINALIZED)
        finalise.assert_called_once()

    def test_a_no_answer_inconclusive_row_also_lets_the_case_finalise(self):
        self.test_reconcile_waits_for_the_provider_row_then_finalises(result=NO_ANSWER)

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
