"""connectors.engines.refresh / apply_result: reconcile reads job results through the engine,
with the effect CortexJobManager.get_cortex_jobs_results and update_single_job had."""
from datetime import timedelta
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from case_handler.lifecycle import LifecycleState
from case_handler.models import Case
from common.http_client import BREAKERS
from connectors import engines
from connectors.base import (
    FETCH_GONE,
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
from connectors.models import ConnectorState
from connectors.registry import ConnectorRegistry
from cortex_job.cortex_utils.reconciliation import reconcile_case_core
from cortex_job.models import Analyzer, AnalyzerReport, CaseAnalyzerJob
from url_process.models import URL

SUMMARY = {"taxonomies": [{"level": "safe", "namespace": "F", "predicate": "P", "value": "0"}]}
FULL = {"results": ["clean"]}
SCORE = "score_process.scoring.cortex_analyzers.reports.CortexAnalyzerReports.create_and_save_report"


class FakeEngine(Connector):
    manifest = ConnectorManifest(name="fake", version="0.0.1", provides=PROVIDER_KIND_ANALYSIS)
    answers: dict = {}
    fetched: list = []
    finished = None

    def health_check(self):
        return HealthStatus(ok=True)

    def catalog(self, data_type=None, name=None):
        return [CatalogEntry("vt", "VT", ("url",))]

    def start(self, analyzer, data_type, value):
        return StartResult("j9", finished=type(self).finished)

    def fetch(self, job_id):
        type(self).fetched.append(job_id)
        return type(self).answers.get(job_id, FetchResult(FETCH_UNKNOWN))


CONFIGS = {"integrations.fake": {"stale_job_timeout_seconds": 600}}


class EngineTestBase(TestCase):
    def setUp(self):
        patcher = mock.patch.dict(BREAKERS)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.registry = ConnectorRegistry()
        self.registry.register(FakeEngine)
        for target in ("connectors.engines.registry", "connectors.delivery.registry",
                       "connectors.dispatch.registry"):
            patcher = mock.patch(target, self.registry)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch("settings.config.get_section", side_effect=lambda n: CONFIGS.get(n, {}))
        patcher.start()
        self.addCleanup(patcher.stop)
        FakeEngine.answers, FakeEngine.fetched, FakeEngine.finished = {}, [], None
        ConnectorState.objects.create(name="fake", enabled=True)
        user = get_user_model().objects.create_user(username="refresh", password="x")
        self.case = Case.objects.create(description="", reporter=user)
        self.url = URL.objects.create(address="http://phish.example/login")
        self.analyzer = Analyzer.objects.create(
            name="VT", analyzer_cortex_id="fake:vt", weight=0.2, source="fake")

    def row(self, job_id="fake-j1", case=None, data_type="url", status="InProgress", age=0):
        report = AnalyzerReport.objects.create(
            cortex_job_id=job_id, type=data_type, status=status, analyzer=self.analyzer,
            url=self.url, level="info", confidence=0, score=0,
            report_summary={"ongoing": "analysis"}, report_full={"ongoing": "analysis"},
            report_taxonomy={"ongoing": "analysis"},
        )
        caj = CaseAnalyzerJob.objects.create(
            case=case or self.case, cortex_job_id=job_id, analyzer=self.analyzer,
            analyzer_report=report, status=status,
        )
        if age:
            CaseAnalyzerJob.objects.filter(pk=caj.pk).update(created_at=timezone.now() - timedelta(seconds=age))
            caj.refresh_from_db()
        return caj

    def answer(self, job_id, *args, **kwargs):
        FakeEngine.answers[job_id] = FetchResult(*args, **kwargs)

    def refresh(self, caj, cache=None):
        engines.refresh(caj, cache)
        caj.refresh_from_db()
        caj.analyzer_report.refresh_from_db()
        return caj, caj.analyzer_report


class RefreshTest(EngineTestBase):
    def test_success_writes_summary_taxonomy_full_and_scores(self):
        caj = self.row()
        self.answer("j1", FETCH_RESULT, "Success", SUMMARY, FULL, data_type="url")
        with mock.patch(SCORE) as score:
            caj, report = self.refresh(caj)
        self.assertEqual(FakeEngine.fetched, ["j1"])  # the engine sees its own job id
        self.assertEqual((report.status, report.report_summary, report.report_taxonomy, report.report_full),
                         ("Success", SUMMARY, SUMMARY["taxonomies"], FULL))
        score.assert_called_once_with(report, self.url.address, None)
        self.assertEqual(caj.status, "Success")
        self.assertIsNotNone(caj.completed_at)

    def test_unknown_leaves_status_and_timestamps_untouched(self):
        caj = self.row()
        rows = (CaseAnalyzerJob.objects.filter(pk=caj.pk), AnalyzerReport.objects.filter(pk=caj.analyzer_report_id))
        before = [q.values().get() for q in rows]
        with mock.patch(SCORE) as score:
            self.refresh(caj)
        self.assertEqual([q.values().get() for q in rows], before)
        self.assertEqual(FakeEngine.fetched, ["j1"])
        score.assert_not_called()

    def test_non_analysis_source_with_a_report_is_skipped(self):
        class Plain(Connector):
            manifest = ConnectorManifest(name="plain", version="0.0.1")

            def health_check(self):
                return HealthStatus(ok=True)

        self.registry.register(Plain)
        self.analyzer.source = "plain"
        self.analyzer.save()
        caj = self.row()
        caj, report = self.refresh(caj)  # must not raise
        self.assertEqual((report.status, caj.status), ("InProgress", "InProgress"))
        self.assertEqual(FakeEngine.fetched, [])

    def test_a_failing_fetch_leaves_the_row_and_does_not_raise(self):
        caj = self.row()
        with mock.patch.object(FakeEngine, "fetch", side_effect=NotImplementedError):
            caj, report = self.refresh(caj)
        self.assertEqual((report.status, caj.status), ("InProgress", "InProgress"))

    def test_null_stale_timeout_falls_back_to_7200(self):
        caj = self.row(age=3000)  # past 600s but inside 7200s
        self.answer("j1", FETCH_RESULT, "InProgress", None, None, data_type="url")
        with mock.patch.dict(CONFIGS, {"integrations.fake": {"stale_job_timeout_seconds": None}}):
            caj, report = self.refresh(caj)
        self.assertEqual(report.status, "InProgress")

    def test_gone_sets_deleted(self):
        caj = self.row()
        self.answer("j1", FETCH_GONE)
        caj, report = self.refresh(caj)
        self.assertEqual((report.status, caj.status), ("Deleted", "Deleted"))
        self.assertIsNotNone(caj.completed_at)

    def test_data_type_mismatch_writes_nothing(self):
        caj = self.row()
        self.answer("j1", FETCH_RESULT, "Success", SUMMARY, FULL, data_type="ip")
        with mock.patch(SCORE) as score:
            caj, report = self.refresh(caj)
        self.assertEqual((report.status, report.report_summary, caj.status),
                         ("InProgress", {"ongoing": "analysis"}, "InProgress"))
        score.assert_not_called()

    def test_mail_body_accepts_a_file_job_and_empty_data_type_is_not_checked(self):
        caj = self.row()
        AnalyzerReport.objects.filter(pk=caj.analyzer_report_id).update(type="mail_body")
        caj.refresh_from_db()
        self.answer("j1", FETCH_RESULT, "Failure", data_type="file")
        caj2 = self.row("fake-j2")
        self.answer("j2", FETCH_RESULT, "Failure")
        self.assertEqual(self.refresh(caj)[1].status, "Failure")
        self.assertEqual(self.refresh(caj2)[1].status, "Failure")

    def test_no_body_keeps_the_status_and_still_scores_on_success(self):
        caj = self.row()
        self.answer("j1", FETCH_RESULT, "Success", data_type="url")
        with mock.patch(SCORE) as score:
            caj, report = self.refresh(caj)
        self.assertEqual((report.status, report.report_summary, caj.status),
                         ("InProgress", {"ongoing": "analysis"}, "InProgress"))
        score.assert_called_once()

    def test_failure_without_body_is_written(self):
        # Cortex's failure report carries errorMessage, never summary or full.
        caj = self.row()
        self.answer("j1", FETCH_RESULT, "Failure", data_type="url")
        with mock.patch(SCORE) as score:
            caj, report = self.refresh(caj)
        self.assertEqual((report.status, caj.status), ("Failure", "Failure"))
        score.assert_not_called()

    def test_pending_row_past_the_engine_timeout_fails(self):
        young, old = self.row("fake-j1", age=60), self.row("fake-j2", age=700)
        self.assertEqual(self.refresh(young)[0].status, "InProgress")
        caj, report = self.refresh(old)
        self.assertEqual((report.status, caj.status), ("Failure", "Failure"))

    def test_default_timeout_is_two_hours(self):
        CONFIGS["integrations.fake"] = {}
        self.addCleanup(CONFIGS.__setitem__, "integrations.fake", {"stale_job_timeout_seconds": 600})
        self.assertEqual(self.refresh(self.row("fake-j1", age=7000))[0].status, "InProgress")
        self.assertEqual(self.refresh(self.row("fake-j2", age=7300))[0].status, "Failure")

    def test_one_fetch_per_job_id_when_two_cases_share_it(self):
        other = Case.objects.create(description="", reporter=self.case.reporter)
        first = self.row()
        second = CaseAnalyzerJob.objects.create(
            case=other, cortex_job_id="fake-j1", analyzer=self.analyzer,
            analyzer_report=first.analyzer_report, status="InProgress")
        self.answer("j1", FETCH_RESULT, "Success", SUMMARY, FULL, data_type="url")
        cache = {}
        with mock.patch(SCORE):
            self.refresh(first, cache)
            self.refresh(second, cache)
        self.assertEqual(FakeEngine.fetched, ["j1"])
        self.assertEqual(second.status, "Success")

    def test_provider_row_without_report_is_skipped(self):
        caj = CaseAnalyzerJob.objects.create(
            case=self.case, cortex_job_id="provider-1", analyzer=self.analyzer, status="InProgress")
        engines.refresh(caj, {})
        self.assertEqual(FakeEngine.fetched, [])
        caj.refresh_from_db()
        self.assertEqual(caj.status, "InProgress")

    def test_unregistered_engine_is_skipped_with_a_warning(self):
        caj = self.row()
        Analyzer.objects.filter(pk=self.analyzer.pk).update(source="gone_engine")
        caj = CaseAnalyzerJob.objects.select_related("analyzer", "analyzer_report").get(pk=caj.pk)
        with self.assertLogs("connectors.engines", "WARNING"):
            engines.refresh(caj, {})
        self.assertEqual(FakeEngine.fetched, [])

    @mock.patch("cortex_job.cortex_utils.reconciliation.emit_connector_event")
    @mock.patch("cortex_job.cortex_utils.reconciliation.finalise")
    def test_disabled_engine_row_is_refreshed_and_the_case_finalises(self, finalise, _emit):
        ConnectorState.objects.filter(name="fake").update(enabled=False)
        self.case.dispatched_at = timezone.now()
        self.case.save(update_fields=["dispatched_at"])
        self.row()
        self.answer("j1", FETCH_RESULT, "Success", SUMMARY, FULL, data_type="url")
        with mock.patch(SCORE):
            reconcile_case_core(self.case)
        self.case.refresh_from_db()
        self.assertEqual(FakeEngine.fetched, ["j1"])
        self.assertEqual(self.case.lifecycle_state, LifecycleState.FINALIZED)
        finalise.assert_called_once()


class ApplyResultTest(TestCase):
    def test_returns_changed_fields(self):
        report = AnalyzerReport(status="InProgress", report_summary={}, report_full={}, report_taxonomy={})
        fields = engines.apply_result(report, FetchResult(FETCH_RESULT, "Success", SUMMARY, FULL))
        self.assertEqual(fields, ["status", "report_summary", "report_taxonomy", "report_full"])
        self.assertEqual(engines.apply_result(report, FetchResult(FETCH_RESULT, "Success", SUMMARY, FULL)), [])

    def test_body_is_ignored_unless_success(self):
        report = AnalyzerReport(status="Waiting", report_summary={}, report_full={}, report_taxonomy={})
        self.assertEqual(engines.apply_result(report, FetchResult(FETCH_RESULT, "InProgress", SUMMARY, FULL)),
                         ["status"])
        self.assertEqual(report.report_summary, {})


class FinishedStartTest(EngineTestBase):
    def dispatch(self):
        with mock.patch("connectors.engines._roles", return_value={}):
            return engines.dispatch(self.url, "url", self.case)

    def test_finished_start_is_stored_and_the_row_closed(self):
        FakeEngine.finished = FetchResult(FETCH_RESULT, "Success", SUMMARY, FULL, data_type="url")
        with mock.patch(SCORE) as score:
            self.assertEqual(self.dispatch(), ["fake-j9"])
        caj = CaseAnalyzerJob.objects.get()
        report = caj.analyzer_report
        self.assertEqual((caj.status, report.status, report.report_summary, report.report_full),
                         ("Success", "Success", SUMMARY, FULL))
        self.assertIsNotNone(caj.completed_at)
        score.assert_called_once_with(report, self.url.address, None)

    def test_pending_start_stays_pending(self):
        self.assertEqual(self.dispatch(), ["fake-j9"])
        caj = CaseAnalyzerJob.objects.get()
        self.assertEqual((caj.status, caj.analyzer_report.status, caj.completed_at),
                         ("InProgress", "InProgress", None))
