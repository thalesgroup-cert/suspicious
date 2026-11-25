"""Pipeline acceptance for the analysis-engine layer, no network: cases dispatched through
engines.dispatch and closed by reconcile_case_core with the real finalise and scoring."""
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from case_handler.lifecycle import LifecycleState
from case_handler.models import Case, CaseHasFileOrMail, CaseHasNonFileIocs
from common.http_client import BREAKERS
from connectors import engines
from connectors.base import (
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
from connectors.contrib.cortex.connector import CortexConnector
from connectors.models import ConnectorState
from connectors.registry import ConnectorRegistry
from cortex_job.cortex_utils.case_targets import collect_case_targets
from cortex_job.cortex_utils.reconciliation import reconcile_case_core
from cortex_job.models import CaseAnalyzerJob
from mail_feeder.models import Mail, MailHeader
from url_process.models import URL

MALICIOUS = {"taxonomies": [{"level": "malicious", "namespace": "Fake", "predicate": "Verdict", "value": "bad"}]}
FULL = {"results": ["phish"]}
DONE = "All analyzers completed successfully. You can now view the full results."


class AcceptanceEngine(Connector):
    manifest = ConnectorManifest(name="accept", version="0.0.1", provides=PROVIDER_KIND_ANALYSIS)
    OFFERED = [
        CatalogEntry("hdr", "Accept_Header", ("mail",)),
        CatalogEntry("url", "Accept_URL", ("url",)),
    ]
    answers: dict = {}
    started: list = []

    def health_check(self):
        return HealthStatus(ok=True)

    def catalog(self, data_type=None, name=None):
        return [e for e in self.OFFERED if (name and e.name == name) or (data_type and data_type in e.data_types)]

    def start(self, analyzer, data_type, value):
        type(self).started.append((analyzer.name, data_type))
        return StartResult(f"{analyzer.id}-1")

    def fetch(self, job_id):
        return type(self).answers.get(job_id, FetchResult(FETCH_UNKNOWN))


CONFIGS = {
    "integrations.cortex": {"url": "http://cortex:9001", "api_key": "k", "analyzers": {"header": "Accept_Header"}},
    "integrations.accept": {},
}


class EngineAcceptanceTest(TestCase):
    def setUp(self):
        patcher = mock.patch.dict(BREAKERS)
        patcher.start()
        self.addCleanup(patcher.stop)
        registry = ConnectorRegistry()
        registry.register(AcceptanceEngine)
        registry.register(CortexConnector)
        for target in ("connectors.engines.registry", "connectors.delivery.registry",
                       "connectors.dispatch.registry"):
            patcher = mock.patch(target, registry)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch("settings.config.get_section", side_effect=lambda n: dict(CONFIGS.get(n, {})))
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch("cortex_job.cortex_utils.reconciliation.emit_connector_event")
        self.emit = patcher.start()
        self.addCleanup(patcher.stop)
        # Cortex is mocked at the connector edge: it must never be reached when disabled.
        self.cx_catalog = self._patch_cortex("catalog", return_value=[CatalogEntry("cx-url", "Cortex_URL", ("url",))])
        self.cx_start = self._patch_cortex("start", return_value=StartResult("cxjob1"))
        self.cx_fetch = self._patch_cortex("fetch", return_value=FetchResult(FETCH_UNKNOWN))
        AcceptanceEngine.answers, AcceptanceEngine.started = {}, []
        ConnectorState.objects.create(name="accept", enabled=True)
        ConnectorState.objects.create(name="cortex", enabled=False)
        self.user = get_user_model().objects.create_user(username="accept", password="x")

    def _patch_cortex(self, op, **kwargs):
        patcher = mock.patch.object(CortexConnector, op, autospec=False, **kwargs)
        self.addCleanup(patcher.stop)
        return patcher.start()

    def _case(self, **links):
        return Case.objects.create(status="On Going", description="", reporter=self.user,
                                   dispatched_at=timezone.now(), **links)

    def url_case(self, address="http://phish.example/login"):
        case = self._case()
        case.nonFileIocs = CaseHasNonFileIocs.objects.create(case=case, url=URL.objects.create(address=address))
        case.save(update_fields=["nonFileIocs"])
        return case

    def mail_case(self):
        header = MailHeader.objects.create(header_value="From: ceo@evil.example", fuzzy_hash="hdr1")
        mail = Mail.objects.create(subject="s", reportedBy="r", date=timezone.now(), to="t",
                                   mail_id="m1", mail_header=header)
        case = self._case()
        case.fileOrMail = CaseHasFileOrMail.objects.create(case=case, mail=mail)
        case.save(update_fields=["fileOrMail"])
        return case

    def dispatch(self, case):
        """What the submission paths do: one dispatch per analysable target."""
        for target, data_type in collect_case_targets(case):
            engines.dispatch(target, data_type, case)

    def answer(self, job_id, data_type):
        AcceptanceEngine.answers[job_id] = FetchResult(FETCH_RESULT, "Success", MALICIOUS, FULL, data_type=data_type)

    def reconcile(self, case):
        reconcile_case_core(case)
        case.refresh_from_db()
        return case

    def sources(self, case):
        return sorted(CaseAnalyzerJob.objects.filter(case=case).values_list("analyzer__source", flat=True))

    def assert_finalised_from_engine(self, case):
        self.assertEqual(case.lifecycle_state, LifecycleState.FINALIZED)
        self.assertEqual(case.description, DONE)
        report = CaseAnalyzerJob.objects.get(case=case).analyzer_report
        self.assertEqual((report.status, report.report_summary, report.report_full), ("Success", MALICIOUS, FULL))
        self.emit.assert_called_once_with("case_finalised", case)

    # ── cortex disabled, fake engine enabled ───────────────────────────────

    def test_mail_case_finalises_from_the_fake_engine_only(self):
        case = self.mail_case()
        self.dispatch(case)
        self.assertEqual(AcceptanceEngine.started, [("Accept_Header", "mail_header")])
        self.assertEqual(self.sources(case), ["accept"])
        self.assertEqual(CaseAnalyzerJob.objects.get(case=case).cortex_job_id, "accept-hdr-1")
        self.cx_catalog.assert_not_called()
        self.cx_start.assert_not_called()

        case = self.reconcile(case)  # nothing back yet: waits
        self.assertEqual(case.lifecycle_state, LifecycleState.ANALYZING)
        self.answer("hdr-1", "mail_header")
        self.assert_finalised_from_engine(self.reconcile(case))
        self.cx_fetch.assert_not_called()

    def test_url_case_finalises_from_the_fake_engine_only(self):
        case = self.url_case()
        self.dispatch(case)
        self.assertEqual(AcceptanceEngine.started, [("Accept_URL", "url")])
        self.assertEqual(self.sources(case), ["accept"])
        self.cx_catalog.assert_not_called()
        self.cx_start.assert_not_called()

        self.answer("url-1", "url")
        self.assert_finalised_from_engine(self.reconcile(case))
        self.cx_fetch.assert_not_called()

    # ── both enabled ───────────────────────────────────────────────────────

    def test_with_both_enabled_one_case_holds_both_and_waits_for_both(self):
        ConnectorState.objects.filter(name="cortex").update(enabled=True)
        case = self.url_case()
        self.dispatch(case)
        self.assertEqual(self.sources(case), ["accept", "cortex"])
        self.assertEqual(
            sorted(CaseAnalyzerJob.objects.filter(case=case).values_list("cortex_job_id", flat=True)),
            ["accept-url-1", "cxjob1"],
        )

        self.answer("url-1", "url")  # the fake engine answers, Cortex not yet
        case = self.reconcile(case)
        self.assertEqual(case.lifecycle_state, LifecycleState.ANALYZING)
        self.assertEqual(
            dict(CaseAnalyzerJob.objects.filter(case=case).values_list("analyzer__source", "status")),
            {"accept": "Success", "cortex": "InProgress"},
        )
        self.cx_fetch.assert_called_with("cxjob1")

        self.cx_fetch.return_value = FetchResult(FETCH_RESULT, "Success", MALICIOUS, FULL, data_type="url")
        case = self.reconcile(case)
        self.assertEqual(case.lifecycle_state, LifecycleState.FINALIZED)
        self.assertEqual(case.description, DONE)
        self.assertEqual(set(CaseAnalyzerJob.objects.filter(case=case).values_list("status", flat=True)), {"Success"})

    # ── disabled while in flight ───────────────────────────────────────────

    def test_a_disabled_engines_in_flight_job_is_fetched_and_the_case_finalises(self):
        case = self.url_case()
        self.dispatch(case)
        ConnectorState.objects.filter(name="accept").update(enabled=False)

        self.answer("url-1", "url")
        self.assert_finalised_from_engine(self.reconcile(case))
        self.assertEqual(engines.enabled_engines(), [])
